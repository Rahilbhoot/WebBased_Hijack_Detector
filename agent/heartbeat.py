"""Agent Heartbeat Service for Endpoint Health Reporting (PRD Section 10 & Phase 12).

Periodically transmits device health telemetry to the cloud endpoint:
- Device ID & Hostname
- OS Version & Agent Version
- Process Uptime (seconds)
- Event Outbox Queue Backlog Size
- Running count of transmitted events
"""

from __future__ import annotations

import logging
import platform
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from agent.config import AgentConfig, load_config
from agent.local_store import LocalStore

logger = logging.getLogger("agent.heartbeat")


def get_system_os_version() -> str:
    """Returns a clean operating system version string."""
    try:
        return f"{platform.system()} {platform.release()} ({platform.version()})"
    except Exception:
        return "Windows"


class HeartbeatSender:
    """Constructs and transmits heartbeat payloads to the cloud API Gateway."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        store: Optional[LocalStore] = None,
        session: Optional[requests.Session] = None,
    ):
        self.config = config or load_config()
        self.store = store or LocalStore(db_path=self.config.queue_file)
        self.session = session or requests.Session()
        self.start_time: float = time.time()
        self.total_events_sent: int = 0

    @property
    def uptime_seconds(self) -> int:
        return int(time.time() - self.start_time)

    def record_events_sent(self, count: int) -> None:
        """Increments the running count of successfully transmitted events."""
        if count > 0:
            self.total_events_sent += count

    def get_queue_size(self) -> int:
        """Retrieves count of pending buffered event records in SQLite outbox."""
        try:
            stats = self.store.get_outbox_stats()
            return int(stats.get("pending_events", 0))
        except Exception as e:
            logger.debug(f"Could not read outbox queue stats: {e}")
            return 0

    def build_payload(self) -> Dict[str, Any]:
        """Constructs the canonical heartbeat payload."""
        now_iso = datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()

        return {
            "device_id": self.config.device_id,
            "agent_version": "1.0.0",
            "uptime_seconds": self.uptime_seconds,
            "timestamp": now_iso,
            "os_version": get_system_os_version(),
            "hostname": hostname,
            "event_queue_size": self.get_queue_size(),
            "total_events_sent": self.total_events_sent,
        }

    def send_heartbeat(self) -> bool:
        """Transmits a single heartbeat to the cloud API Gateway."""
        if not self.config.api_endpoint or self.config.standalone_mode:
            logger.debug("Skipping heartbeat: standalone mode or missing api_endpoint.")
            return True

        url = f"{self.config.api_endpoint.rstrip('/')}/heartbeat"
        payload = self.build_payload()
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
        }

        try:
            logger.debug(f"Sending heartbeat to {url} (uptime={payload['uptime_seconds']}s)...")
            resp = self.session.post(url, json=payload, headers=headers, timeout=8.0)

            if resp.status_code == 200:
                logger.info(
                    f"Heartbeat delivered successfully for device '{self.config.device_id}' "
                    f"(uptime={payload['uptime_seconds']}s, queue={payload['event_queue_size']})."
                )
                return True
            elif resp.status_code in (401, 403):
                logger.error(
                    f"Heartbeat rejected (HTTP {resp.status_code}): Invalid or revoked API key. "
                    "Contact SOC administrator to re-enroll this endpoint."
                )
                return False
            else:
                logger.warning(
                    f"Heartbeat returned HTTP {resp.status_code}: {resp.text}"
                )
                return False

        except (requests.RequestException, Exception) as err:
            logger.warning(f"Failed to transmit heartbeat: {err}")
            return False


class HeartbeatService:
    """Runs HeartbeatSender periodically in a background thread."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        store: Optional[LocalStore] = None,
        sender: Optional[HeartbeatSender] = None,
    ):
        self.config = config or load_config()
        self.sender = sender or HeartbeatSender(config=self.config, store=store)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Starts the background heartbeat sender loop."""
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="HeartbeatServiceThread",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"HeartbeatService started (interval={self.config.heartbeat_interval_seconds}s)."
        )

    def stop(self, timeout: float = 3.0) -> None:
        """Signals the background loop to stop and waits for exit."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("HeartbeatService stopped.")

    def _run_loop(self) -> None:
        """Main periodic loop."""
        # Send initial startup heartbeat immediately
        self.sender.send_heartbeat()

        interval = max(5, int(self.config.heartbeat_interval_seconds))
        while not self._stop_event.is_set():
            # Wait for interval or until stopped
            if self._stop_event.wait(timeout=interval):
                break
            self.sender.send_heartbeat()
