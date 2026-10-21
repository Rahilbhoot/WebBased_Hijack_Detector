"""Standalone local detection engine and alert formatter.

Processes normalized events entirely locally on the Windows endpoint using the RuleEngine
and Correlator, persists findings to SQLite, and outputs alerts with clear severity badges.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from agent.config import AgentConfig, load_config
from agent.correlator import EventCorrelator
from agent.local_store import LocalStore
from agent.models import Alert, NormalizedEvent
from agent.rule_engine import RuleEngine, calculate_severity

logger = logging.getLogger("agent.standalone")

# ANSI Color codes for terminal alert output
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


class StandaloneDetector:
    """Coordinates local detection, correlation, SQLite persistence, and alert formatting."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        store: Optional[LocalStore] = None,
        rule_engine: Optional[RuleEngine] = None,
        correlator: Optional[EventCorrelator] = None,
    ):
        self.config = config or load_config()
        self.store = store or LocalStore(db_path=self.config.local_db_file)
        self.rule_engine = rule_engine or RuleEngine(
            rules_path=self.config.rules_file,
            whitelist_path=self.config.whitelist_file,
        )

        corr_path = self.config.rules_file.parent / "correlation_rules.yaml"
        self.correlator = correlator or EventCorrelator(correlations_path=corr_path)

    def process_events(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Evaluates a batch of normalized events, persists events and generated alerts."""
        if not events:
            return []

        # 1. Store raw normalized events in local SQLite
        self.store.insert_events(events)

        generated_alerts: List[Alert] = []

        for ev in events:
            # 2. Evaluate against detection rules
            matched_rules = self.rule_engine.evaluate(ev)
            if not matched_rules:
                continue

            matched_ids = [r.id for r in matched_rules]
            base_score = sum(r.base_score for r in matched_rules)
            all_mitre_ids: List[str] = []
            for r in matched_rules:
                all_mitre_ids.extend(r.mitre_ids)

            # 3. Evaluate multi-event correlation sequences
            corr_matches = self.correlator.evaluate(
                device_id=ev.device_id,
                current_event=ev,
                current_rule_ids=matched_ids,
            )

            # Record event in sliding window for future correlation matches
            self.correlator.record_event(ev.device_id, ev, matched_ids)

            correlation_bonus = sum(cm.score_bonus for cm in corr_matches)
            total_score = base_score + correlation_bonus
            severity = calculate_severity(total_score)

            # Combine explanations
            rule_explanations = [r.format_explanation(ev) for r in matched_rules]
            corr_explanations = [cm.explanation for cm in corr_matches]
            full_explanation = "\n".join(rule_explanations + corr_explanations)

            all_rule_ids = matched_ids + [cm.rule_id for cm in corr_matches]

            alert = Alert(
                device_id=ev.device_id,
                timestamp=ev.timestamp,
                rule_ids=all_rule_ids,
                score=total_score,
                severity=severity,
                explanation=full_explanation,
                mitre_ids=list(dict.fromkeys(all_mitre_ids)),  # unique list
                raw_event=ev.to_dict(),
            )

            # 4. Save alert to local SQLite
            self.store.insert_alert(alert)
            generated_alerts.append(alert)

            # 5. Output alert
            self.display_alert(alert)

        # Mark processed
        self.store.mark_events_processed([ev.event_id for ev in events])
        return generated_alerts

    def display_alert(self, alert: Alert) -> None:
        """Formats and outputs alert to console and agent logger."""
        color = COLOR_CYAN
        if alert.severity == "High":
            color = COLOR_RED
        elif alert.severity == "Medium":
            color = COLOR_YELLOW

        div = "=" * 48
        sev_tag = f"[BROWSER HIJACK ALERT - {alert.severity.upper()} RISK]"
        header = (
            f"\n{color}{COLOR_BOLD}{div}{COLOR_RESET}\n"
            f"{color}{COLOR_BOLD}{sev_tag}{COLOR_RESET}\n"
            f"{color}{COLOR_BOLD}{div}{COLOR_RESET}\n"
            f"Device ID:    {alert.device_id}\n"
            f"Timestamp:    {alert.timestamp}\n"
            f"Risk Score:   {alert.score} ({alert.severity})\n"
            f"Rules Fired:  {', '.join(alert.rule_ids)}\n"
            f"MITRE ATT&CK: {', '.join(alert.mitre_ids) if alert.mitre_ids else 'None'}\n"
            f"Explanation:\n{alert.explanation}\n"
            f"{color}----------------------------------------------------{COLOR_RESET}\n"
        )

        print(header)
        logger.warning(
            f"[{alert.severity}] Browser hijack alert on {alert.device_id}: "
            f"Score={alert.score}, Rules={','.join(alert.rule_ids)}"
        )
