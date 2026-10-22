"""Multi-event correlation engine for the Browser Hijack Detector (Shared).

Maintains sliding-window event history per device and evaluates correlation sequences
(CR01, CR02, CR03) to detect multi-stage attack chains and assign bonus risk scores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

try:
    from shared.models import NormalizedEvent
except ImportError:
    from agent.models import NormalizedEvent  # type: ignore

logger = logging.getLogger("shared.correlator")


@dataclass
class CorrelationRule:
    """Definition of a multi-event correlation rule."""

    id: str
    name: str
    description: str
    required_rules: List[str]
    time_window_seconds: int
    score_bonus: int
    explanation: str


@dataclass
class HistoryRecord:
    """Historical event entry stored in sliding window."""

    timestamp: datetime
    rule_ids: List[str]
    event_type: str
    summary: str


@dataclass
class CorrelationMatch:
    """Represents a correlation rule that fired."""

    rule_id: str
    name: str
    score_bonus: int
    explanation: str


def parse_iso_utc(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp to timezone-aware datetime."""
    try:
        clean_ts = ts_str.rstrip("Z")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


class EventCorrelator:
    """Tracks per-device event history and evaluates correlation attack patterns."""

    def __init__(self, correlations_path: Optional[Union[str, Path]] = None):
        self.history: Dict[str, List[HistoryRecord]] = {}
        self.rules: List[CorrelationRule] = []

        if correlations_path:
            self.load_rules(correlations_path)

    def load_rules(self, correlations_path: Union[str, Path]) -> None:
        """Loads correlation rule definitions from YAML file."""
        path = Path(correlations_path).resolve()
        if not path.is_file():
            logger.warning(f"Correlation rules file not found at {path}")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self.load_rules_data(data)

    def load_rules_data(self, data: Union[Dict[str, Any], str]) -> None:
        """Loads correlation rule definitions from dictionary or raw YAML string."""
        if isinstance(data, str):
            data = yaml.safe_load(data) or {}

        loaded_rules: List[CorrelationRule] = []
        for c in data.get("correlations", []):
            try:
                loaded_rules.append(
                    CorrelationRule(
                        id=str(c.get("id")),
                        name=str(c.get("name")),
                        description=str(c.get("description", "")),
                        required_rules=[str(r) for r in c.get("required_rules", [])],
                        time_window_seconds=int(c.get("time_window_seconds", 300)),
                        score_bonus=int(c.get("score_bonus", 20)),
                        explanation=str(c.get("explanation", "")).strip(),
                    )
                )
            except Exception as e:
                logger.error(f"Error parsing correlation rule {c.get('id')}: {e}")

        self.rules = loaded_rules
        logger.info(f"Loaded {len(self.rules)} correlation rules.")

    def record_event(
        self, device_id: str, event: NormalizedEvent, matched_rule_ids: List[str]
    ) -> None:
        """Appends an event to the device's sliding window history."""
        if not matched_rule_ids:
            return

        event_dt = parse_iso_utc(event.timestamp)
        summary = (
            f"type={event.type} image={event.process_image} "
            f"cmd={event.command_line} file={event.file_path}"
        )

        record = HistoryRecord(
            timestamp=event_dt,
            rule_ids=list(matched_rule_ids),
            event_type=event.type,
            summary=summary,
        )

        dev_history = self.history.setdefault(device_id, [])
        dev_history.append(record)
        self.prune(device_id, current_time=event_dt)

    def prune(
        self,
        device_id: Optional[str] = None,
        max_age_seconds: int = 3600,
        current_time: Optional[datetime] = None,
    ) -> None:
        """Evicts history records older than max_age_seconds relative to current stream time."""
        targets = [device_id] if device_id else list(self.history.keys())

        for d_id in targets:
            records = self.history.get(d_id, [])
            if not records:
                continue

            ref_time = current_time or records[-1].timestamp
            self.history[d_id] = [
                rec
                for rec in records
                if 0 <= (ref_time - rec.timestamp).total_seconds() <= max_age_seconds
            ]

    def evaluate(
        self, device_id: str, current_event: NormalizedEvent, current_rule_ids: List[str]
    ) -> List[CorrelationMatch]:
        """Evaluates current event and recent device history against correlation rules."""
        if not current_rule_ids and not self.rules:
            return []

        current_dt = parse_iso_utc(current_event.timestamp)
        dev_history = self.history.get(device_id, [])
        matches: List[CorrelationMatch] = []

        for cr in self.rules:
            # Check CR01: BH002 followed by BH001 within time window
            if cr.id == "CR01":
                if "BH001" in current_rule_ids:
                    has_bh002 = any(
                        "BH002" in rec.rule_ids
                        and 0
                        <= (current_dt - rec.timestamp).total_seconds()
                        <= cr.time_window_seconds
                        for rec in dev_history
                    )
                    if has_bh002:
                        matches.append(
                            CorrelationMatch(
                                rule_id=cr.id,
                                name=cr.name,
                                score_bonus=cr.score_bonus,
                                explanation=cr.explanation,
                            )
                        )

            # Check CR02: BH003 + BH004 within time window (in either order)
            elif cr.id == "CR02":
                triggered = False
                if "BH003" in current_rule_ids:
                    has_bh004 = any(
                        "BH004" in rec.rule_ids
                        and abs((current_dt - rec.timestamp).total_seconds())
                        <= cr.time_window_seconds
                        for rec in dev_history
                    )
                    if has_bh004:
                        triggered = True
                elif "BH004" in current_rule_ids:
                    has_bh003 = any(
                        "BH003" in rec.rule_ids
                        and abs((current_dt - rec.timestamp).total_seconds())
                        <= cr.time_window_seconds
                        for rec in dev_history
                    )
                    if has_bh003:
                        triggered = True

                if triggered:
                    matches.append(
                        CorrelationMatch(
                            rule_id=cr.id,
                            name=cr.name,
                            score_bonus=cr.score_bonus,
                            explanation=cr.explanation,
                        )
                    )

            # Check CR03: Any previous detection followed by BH007 (log clearing)
            elif cr.id == "CR03":
                if "BH007" in current_rule_ids:
                    prior_detections = any(
                        any(r != "BH007" for r in rec.rule_ids)
                        and 0
                        <= (current_dt - rec.timestamp).total_seconds()
                        <= cr.time_window_seconds
                        for rec in dev_history
                    )
                    if prior_detections:
                        matches.append(
                            CorrelationMatch(
                                rule_id=cr.id,
                                name=cr.name,
                                score_bonus=cr.score_bonus,
                                explanation=cr.explanation,
                            )
                        )

        return matches
