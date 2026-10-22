"""Event sender with HTTPS batching and offline SQLite buffering.

Transmits normalized event batches to the cloud ingestion API Gateway.
If network connectivity is lost, batches are queued into the local SQLite outbox
and drained automatically when connectivity resumes (PRD Section 6.1 FR-A4, FR-A5).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from agent.config import AgentConfig, load_config
from agent.local_store import LocalStore
from agent.models import NormalizedEvent

logger = logging.getLogger("agent.sender")


class EventSender:
    """Manages event transmission to the cloud API with resilient offline queueing."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        store: Optional[LocalStore] = None,
        session: Optional[requests.Session] = None,
    ):
        self.config = config or load_config()
        self.store = store or LocalStore(db_path=self.config.queue_file)
        self.session = session or requests.Session()
        self.last_drain_attempt: float = 0.0

    def send_events(self, events: List[NormalizedEvent]) -> bool:
        """Sends a batch of normalized events or queues them locally if offline."""
        if not events:
            return True

        payload: Dict[str, Any] = {
            "device_id": self.config.device_id,
            "agent_version": "1.0.0",
            "events": [ev.to_dict() for ev in events],
        }

        # If running offline or no cloud endpoint configured, buffer or skip
        if not self.config.api_endpoint or self.config.standalone_mode:
            logger.debug(
                "Cloud endpoint not configured or standalone mode active. Skipping cloud send."
            )
            return True

        url = f"{self.config.api_endpoint.rstrip('/')}/events"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
        }

        try:
            logger.debug(f"Transmitting batch of {len(events)} event(s) to {url}...")
            resp = self.session.post(url, json=payload, headers=headers, timeout=10.0)

            # 202 Accepted (standard) or 200 OK
            if resp.status_code in (200, 202):
                logger.info(f"Successfully transmitted {len(events)} event(s) to cloud ingestion.")
                # After successful send, try draining pending outbox queue
                self.drain_outbox()
                return True

            elif 400 <= resp.status_code < 500:
                logger.error(
                    f"Cloud rejected event batch (HTTP {resp.status_code}): {resp.text}. "
                    "Will not retry invalid payload."
                )
                return False

            else:
                logger.warning(
                    f"Cloud returned HTTP {resp.status_code}. Buffering batch in offline queue."
                )
                self.store.enqueue_outbox(payload, len(events))
                return False

        except (requests.RequestException, Exception) as err:
            logger.warning(
                f"Network error transmitting events: {err}. Buffering batch in offline queue."
            )
            self.store.enqueue_outbox(payload, len(events))
            return False

    def drain_outbox(self, max_batches: int = 5) -> int:
        """Attempts to drain buffered batches from the offline outbox queue."""
        if not self.config.api_endpoint or self.config.standalone_mode:
            return 0

        # Enforce rate/backoff limit between drain attempts (minimum 5s)
        now = time.time()
        if now - self.last_drain_attempt < 5.0:
            return 0
        self.last_drain_attempt = now

        pending = self.store.peek_outbox(limit=max_batches)
        if not pending:
            return 0

        logger.info(f"Attempting to drain {len(pending)} buffered batch(es) from offline outbox...")
        url = f"{self.config.api_endpoint.rstrip('/')}/events"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
        }

        drained_count = 0
        for item in pending:
            outbox_id = item["id"]
            payload = item["payload"]
            try:
                resp = self.session.post(url, json=payload, headers=headers, timeout=10.0)
                if resp.status_code in (200, 202):
                    self.store.acknowledge_outbox(outbox_id)
                    drained_count += 1
                else:
                    self.store.increment_outbox_retry(outbox_id)
                    # Stop draining this cycle on server/network failure
                    break
            except Exception as e:
                logger.debug(f"Drain attempt failed for outbox batch {outbox_id}: {e}")
                self.store.increment_outbox_retry(outbox_id)
                break

        if drained_count > 0:
            logger.info(f"Drained {drained_count} batch(es) from offline outbox.")
        return drained_count
