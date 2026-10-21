"""Windows Event Log Collector for the Browser Hijack Detector Agent.

Collects events from Sysmon, Security, System, and PowerShell event channels,
filters by Event ID, persists bookmarks across restarts, and handles errors gracefully.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# Attempt import of win32evtlog; handled gracefully on non-Windows/mock setups
try:
    import pywintypes  # type: ignore
    import win32evtlog  # type: ignore

    HAS_WIN32EVTLOG = True
except ImportError:
    win32evtlog = None
    pywintypes = None
    HAS_WIN32EVTLOG = False

from agent.config import AgentConfig, ChannelConfig, load_config
from agent.logger import setup_logger

logger = logging.getLogger("agent.collector")

XML_NAMESPACE = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


class BookmarkManager:
    """Tracks and persists the last processed EventRecordID per channel."""

    def __init__(self, bookmark_path: Path, logger_instance: Optional[logging.Logger] = None):
        self.bookmark_path = Path(bookmark_path).resolve()
        self.log = logger_instance or logger
        self.bookmarks: Dict[str, int] = {}
        self.load()

    def load(self) -> Dict[str, int]:
        """Loads bookmarks from disk. Recovers gracefully if file is corrupted."""
        if not self.bookmark_path.exists():
            self.bookmarks = {}
            return self.bookmarks

        try:
            with open(self.bookmark_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self.bookmarks = {str(k): int(v) for k, v in data.items() if str(v).isdigit()}
                else:
                    self.bookmarks = {}
        except Exception as e:
            self.log.warning(
                f"Corrupt bookmark file at {self.bookmark_path}: {e}. "
                "Backing up and starting fresh."
            )
            try:
                backup_path = self.bookmark_path.with_suffix(".corrupt.bak")
                if self.bookmark_path.exists():
                    os.replace(self.bookmark_path, backup_path)
            except Exception:
                pass
            self.bookmarks = {}

        return self.bookmarks

    def get_last_record_id(self, channel: str) -> Optional[int]:
        """Returns the last-read RecordId for the channel, or None if not set."""
        return self.bookmarks.get(channel)

    def update(self, channel: str, record_id: int) -> None:
        """Updates in-memory bookmark for the channel."""
        current = self.bookmarks.get(channel, 0)
        if record_id > current:
            self.bookmarks[channel] = record_id

    def save(self) -> None:
        """Persists bookmarks to disk atomically using a temporary file."""
        try:
            self.bookmark_path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temp file in the same directory to allow atomic rename
            with tempfile.NamedTemporaryFile(
                "w",
                dir=str(self.bookmark_path.parent),
                delete=False,
                encoding="utf-8",
                suffix=".tmp",
            ) as tf:
                json.dump(self.bookmarks, tf, indent=2)
                temp_name = tf.name

            # Atomic replace (NTFS supported)
            os.replace(temp_name, self.bookmark_path)
        except Exception as e:
            self.log.error(f"Failed to persist bookmarks to {self.bookmark_path}: {e}")

    def reset(self, channel: Optional[str] = None) -> None:
        """Resets bookmark for a specific channel or all channels."""
        if channel:
            self.bookmarks.pop(channel, None)
        else:
            self.bookmarks.clear()
        self.save()


class EventParser:
    """Parses raw Windows Event XML into structured dictionaries."""

    @staticmethod
    def parse_xml(xml_content: str) -> Optional[Dict[str, Any]]:
        """Parses an XML string from EvtRender into a standardized raw event dict."""
        if not xml_content:
            return None

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.warning(f"Failed to parse event XML: {e}")
            return None

        system_elem = root.find("ns:System", XML_NAMESPACE)
        if system_elem is None:
            # Try without namespace if missing
            system_elem = root.find("System")

        if system_elem is None:
            return None

        def get_text(parent: ET.Element, tag: str) -> str:
            val = parent.findtext(f"ns:{tag}", namespaces=XML_NAMESPACE)
            if val is None:
                val = parent.findtext(tag)
            return val or ""

        channel = get_text(system_elem, "Channel")
        event_id_str = get_text(system_elem, "EventID")
        record_id_str = get_text(system_elem, "EventRecordID")
        computer = get_text(system_elem, "Computer")

        # TimeCreated
        time_created = ""
        tc_elem = system_elem.find("ns:TimeCreated", XML_NAMESPACE)
        if tc_elem is None:
            tc_elem = system_elem.find("TimeCreated")
        if tc_elem is not None:
            time_created = tc_elem.get("SystemTime", "")

        event_data: Dict[str, Any] = {}

        # Look in EventData or UserData
        data_parent = root.find("ns:EventData", XML_NAMESPACE)
        if data_parent is None:
            data_parent = root.find("EventData")
        if data_parent is None:
            data_parent = root.find("ns:UserData", XML_NAMESPACE)
        if data_parent is None:
            data_parent = root.find("UserData")

        if data_parent is not None:
            for child in data_parent:
                name = child.get("Name")
                val = child.text or ""
                if name:
                    event_data[name] = val
                else:
                    # Positional data tag
                    event_data.setdefault("_positional", []).append(val)

        return {
            "Channel": channel,
            "EventID": int(event_id_str) if event_id_str.isdigit() else 0,
            "EventRecordID": int(record_id_str) if record_id_str.isdigit() else 0,
            "TimeCreated": time_created,
            "Computer": computer,
            "EventData": event_data,
            "RawXml": xml_content,
        }


class EventCollector:
    """Reads events from Windows Event Logs using bookmarks and XPath filtering."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        bookmark_manager: Optional[BookmarkManager] = None,
        logger_instance: Optional[logging.Logger] = None,
    ):
        self.config = config or load_config()
        self.log = logger_instance or setup_logger(
            name="agent.collector",
            log_file=self.config.log_file,
            log_level=self.config.log_level,
            max_bytes=self.config.log_max_bytes,
            backup_count=self.config.log_backup_count,
        )
        self.bookmarks = bookmark_manager or BookmarkManager(
            self.config.bookmark_file, logger_instance=self.log
        )
        self.missing_channels_warned: Set[str] = set()

    def get_latest_record_id(self, channel: str) -> Optional[int]:
        """Queries the latest event in a channel to find the current highest EventRecordID."""
        if not HAS_WIN32EVTLOG:
            return None

        try:
            query = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*",
            )
            events = win32evtlog.EvtNext(query, 1)
            if events:
                xml_content = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
                parsed = EventParser.parse_xml(xml_content)
                if parsed and parsed.get("EventRecordID"):
                    return int(parsed["EventRecordID"])
        except Exception as e:
            self.log.debug(f"Unable to query latest record ID for channel '{channel}': {e}")
        return None

    def build_query_for_channel(self, channel_cfg: ChannelConfig) -> str:
        """Builds XPath query including both EventRecordID bookmark and EventIDs."""
        last_id = self.bookmarks.get_last_record_id(channel_cfg.name)
        id_clauses = (
            [f"EventID={eid}" for eid in channel_cfg.event_ids] if channel_cfg.event_ids else []
        )

        conditions = []
        if last_id is not None and last_id > 0:
            conditions.append(f"EventRecordID > {last_id}")

        if id_clauses:
            conditions.append(f"({' or '.join(id_clauses)})")

        if not conditions:
            return "*"

        return f"*[System[{' and '.join(conditions)}]]"

    def collect_channel(
        self, channel_cfg: ChannelConfig, max_events: int = 100
    ) -> List[Dict[str, Any]]:
        """Collects new events from a single channel since the last bookmark."""
        if not HAS_WIN32EVTLOG:
            self.log.debug(
                "win32evtlog is not available (non-Windows platform or test environment)."
            )
            return []

        # If this channel has never been bookmarked, initialize bookmark to current head
        # so we don't ingest massive historical archives on initial start
        if self.bookmarks.get_last_record_id(channel_cfg.name) is None:
            latest_id = self.get_latest_record_id(channel_cfg.name)
            if latest_id is not None:
                self.log.info(
                    f"First run for channel '{channel_cfg.name}': "
                    f"bookmarking current record ID {latest_id}."
                )
                self.bookmarks.update(channel_cfg.name, latest_id)
                self.bookmarks.save()
                return []
            else:
                self.bookmarks.update(channel_cfg.name, 0)

        xpath = self.build_query_for_channel(channel_cfg)
        self.log.debug(f"Querying '{channel_cfg.name}' with XPath: {xpath}")

        events_collected: List[Dict[str, Any]] = []
        highest_record_id = self.bookmarks.get_last_record_id(channel_cfg.name) or 0

        try:
            query = win32evtlog.EvtQuery(
                channel_cfg.name,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                xpath,
            )
        except Exception as e:
            err_code = getattr(e, "winerror", None) or (
                e.args[0] if getattr(e, "args", None) else None
            )
            if err_code == 15007:  # ERROR_EVT_CHANNEL_NOT_FOUND
                if channel_cfg.name not in self.missing_channels_warned:
                    self.log.warning(
                        f"Channel '{channel_cfg.name}' not found on this machine "
                        "(e.g. Sysmon not installed). Skipping."
                    )
                    self.missing_channels_warned.add(channel_cfg.name)
            elif err_code == 5:  # ERROR_ACCESS_DENIED
                if channel_cfg.name not in self.missing_channels_warned:
                    self.log.warning(
                        f"Access denied to channel '{channel_cfg.name}'. "
                        "Administrator privileges required to read this log."
                    )
                    self.missing_channels_warned.add(channel_cfg.name)
            else:
                self.log.error(f"Error querying channel '{channel_cfg.name}': {e}")
            return []

        # Fetch events in chunks
        try:
            handles = win32evtlog.EvtNext(query, max_events)
            for handle in handles:
                try:
                    xml_content = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                    parsed = EventParser.parse_xml(xml_content)
                    if parsed:
                        rec_id = parsed.get("EventRecordID", 0)
                        if rec_id > highest_record_id:
                            highest_record_id = rec_id
                        events_collected.append(parsed)
                except Exception as parse_err:
                    self.log.warning(f"Error rendering event XML: {parse_err}")
        except Exception as read_err:
            self.log.error(
                f"Error retrieving events from channel '{channel_cfg.name}': {read_err}"
            )

        # Update bookmark if new events were collected
        if highest_record_id > (self.bookmarks.get_last_record_id(channel_cfg.name) or 0):
            self.bookmarks.update(channel_cfg.name, highest_record_id)

        return events_collected

    def collect_batch(self, max_events_per_channel: int = 100) -> List[Dict[str, Any]]:
        """Collects new events across all configured channels and saves bookmarks."""
        all_events: List[Dict[str, Any]] = []

        for ch in self.config.channels:
            events = self.collect_channel(ch, max_events=max_events_per_channel)
            all_events.extend(events)

        if all_events:
            self.log.info(
                f"Collected {len(all_events)} new event(s) across "
                f"{len(self.config.channels)} channel(s)."
            )
            self.bookmarks.save()

        return all_events

    def run(
        self,
        callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
        poll_interval: Optional[int] = None,
        stop_event: Optional[Any] = None,
    ) -> None:
        """Main loop that polls for new events at regular intervals."""
        interval = poll_interval or self.config.poll_interval_seconds
        self.log.info(f"Starting Event Collector loop (polling every {interval}s)...")

        try:
            while True:
                if stop_event and stop_event.is_set():
                    self.log.info("Stop event received. Exiting collector loop.")
                    break

                events = self.collect_batch(max_events_per_channel=self.config.batch_size)
                if events and callback:
                    try:
                        callback(events)
                    except Exception as cb_err:
                        self.log.error(f"Callback error processing events: {cb_err}")

                time.sleep(interval)
        except KeyboardInterrupt:
            self.log.info("Keyboard interrupt received. Shutting down collector.")
        finally:
            self.bookmarks.save()


if __name__ == "__main__":
    # Ensure project root is in sys.path when executed directly
    root_path = Path(__file__).resolve().parent.parent
    if str(root_path) not in sys.path:
        sys.path.insert(0, str(root_path))

    # Quick standalone test execution
    cfg = load_config()
    print(f"Device ID: {cfg.device_id}")
    print(f"Configured Channels: {[c.name for c in cfg.channels]}")
    collector = EventCollector(cfg)

    def print_events(evts: List[Dict[str, Any]]) -> None:
        for ev in evts:
            ch_name = ev["Channel"]
            eid = ev["EventID"]
            rid = ev["EventRecordID"]
            tc = ev["TimeCreated"]
            print(f"[{ch_name}] EventID={eid} RecordID={rid} Time={tc}")

    print("Running single collection batch...")
    batch = collector.collect_batch()
    print_events(batch)
    print("Done.")
