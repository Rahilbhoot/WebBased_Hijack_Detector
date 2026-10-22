"""Unified Windows Agent Service Entrypoint (PRD Section 6 & Phase 13.8).

Coordinates all agent subsystems:
1. XPath Event Collector (Sysmon, Security, System, PowerShell)
2. Normalization Engine (Schema standardization)
3. Local Detection Engine & Correlation (BH001-BH008, CR01-CR03)
4. Outbox SQLite Buffer & Cloud Event Sender
5. Background Heartbeat Telemetry Service
6. Graceful Windows Service signal and exception handling
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path
from typing import Optional

from agent.collector import EventCollector
from agent.config import AgentConfig, load_config
from agent.correlator import EventCorrelator
from agent.heartbeat import HeartbeatService
from agent.local_store import LocalStore
from agent.logger import setup_logger
from agent.normalizer import normalize
from agent.rule_engine import RuleEngine
from agent.sender import EventSender

logger = logging.getLogger("agent.service")


class HijackDetectorService:
    """Main daemon service managing endpoint collection, detection, and transport."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config: AgentConfig = load_config(config_path)
        setup_logger(
            log_file=self.config.log_file,
            max_bytes=self.config.log_max_bytes,
            backup_count=self.config.log_backup_count,
            log_level=self.config.log_level,
        )

        logger.info(
            f"Initializing Hijack Detector Agent Service for device '{self.config.device_id}' "
            f"(standalone={self.config.standalone_mode})."
        )

        # Initialize persistence & state stores
        self.queue_store = LocalStore(db_path=self.config.queue_file)
        self.alert_store = LocalStore(db_path=self.config.local_db_file)

        # Initialize pipeline components
        self.collector = EventCollector(config=self.config)
        self.rule_engine = RuleEngine(
            rules_path=self.config.rules_file,
            whitelist_path=self.config.whitelist_file,
        )
        corr_path = self.config.rules_file.parent / "correlation_rules.yaml"
        self.correlator = EventCorrelator(correlations_path=corr_path)

        self.sender = EventSender(config=self.config, store=self.queue_store)
        self.heartbeat_service = HeartbeatService(config=self.config, store=self.queue_store)

        self._stop_event = threading.Event()
        self._main_thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = True) -> None:
        """Starts background heartbeat sender and event collection loop."""
        self._stop_event.clear()

        # Start heartbeat telemetry service (cloud mode)
        if not self.config.standalone_mode and self.config.api_endpoint:
            self.heartbeat_service.start()

        if blocking:
            self._setup_signal_handlers()
            self._run_collection_loop()
        else:
            self._main_thread = threading.Thread(
                target=self._run_collection_loop,
                name="AgentCollectionThread",
                daemon=True,
            )
            self._main_thread.start()

    def stop(self) -> None:
        """Signals all subsystems to stop and flushes outbox."""
        logger.info("Stopping Hijack Detector Agent Service...")
        self._stop_event.set()

        # Stop heartbeat
        self.heartbeat_service.stop(timeout=2.0)

        # Drain any pending offline outbox batches before exit if online
        try:
            self.sender.drain_outbox(max_batches=5)
        except Exception as e:
            logger.debug(f"Drain on shutdown error: {e}")

        logger.info("Hijack Detector Agent Service stopped cleanly.")

    def _setup_signal_handlers(self) -> None:
        """Registers OS termination signals for clean shutdown."""
        def handler(sig, frame):
            logger.info(f"Received shutdown signal ({sig}). Initiating graceful stop...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _run_collection_loop(self) -> None:
        """Core collection and detection processing loop."""
        logger.info("Agent event collection loop running.")
        poll_interval = max(1, int(self.config.poll_interval_seconds))

        while not self._stop_event.is_set():
            try:
                # 1. Collect new Windows events across configured channels
                raw_events = self.collector.collect_all()

                if raw_events:
                    # 2. Normalize raw XML/dict events to unified schema
                    normalized_batch = []
                    for raw in raw_events:
                        norm = normalize(raw)
                        if norm:
                            normalized_batch.append(norm)

                    # 3. Local standalone detection & correlation
                    for event in normalized_batch:
                        matched_rules = self.rule_engine.evaluate(event)
                        if matched_rules:
                            matched_ids = [r.id for r in matched_rules]
                            base_score = sum(r.base_score for r in matched_rules)
                            all_mitre_ids = [m for r in matched_rules for m in r.mitre_ids]

                            corr_matches = self.correlator.evaluate(
                                device_id=event.device_id,
                                current_event=event,
                                current_rule_ids=matched_ids,
                            )
                            self.correlator.record_event(event.device_id, event, matched_ids)

                            corr_bonus = sum(cm.score_bonus for cm in corr_matches)
                            total_score = min(100, base_score + corr_bonus)
                            if total_score >= 60:
                                severity = "High"
                            elif total_score >= 30:
                                severity = "Medium"
                            else:
                                severity = "Low"

                            explanations = [r.format_explanation(event) for r in matched_rules] + [
                                cm.explanation for cm in corr_matches
                            ]
                            combined_rule_ids = matched_ids + [cm.rule_id for cm in corr_matches]

                            logger.warning(
                                f"LOCAL ALERT [{severity}]: {', '.join(combined_rule_ids)} "
                                f"(score={total_score}) - {' '.join(explanations)}"
                            )
                            self.alert_store.save_alert({
                                "device_id": event.device_id,
                                "timestamp": event.timestamp,
                                "rule_ids": combined_rule_ids,
                                "score": total_score,
                                "severity": severity,
                                "explanation": " ".join(explanations),
                                "mitre_ids": all_mitre_ids,
                                "raw_event": event.to_dict(),
                            })

                    # 4. Transmit normalized batch to cloud ingestion (or buffer in offline SQLite)
                    if normalized_batch:
                        self.sender.send_events(normalized_batch)
                        self.heartbeat_service.sender.record_events_sent(len(normalized_batch))

                # 5. Periodically attempt draining buffered outbox
                self.sender.drain_outbox()

            except Exception as e:
                logger.error(f"Error in collection loop: {e}", exc_info=True)

            # Wait for next polling cycle
            self._stop_event.wait(timeout=poll_interval)


def main() -> None:
    """CLI / Service entrypoint."""
    service = HijackDetectorService()
    try:
        service.start(blocking=True)
    except KeyboardInterrupt:
        service.stop()


if __name__ == "__main__":
    main()
