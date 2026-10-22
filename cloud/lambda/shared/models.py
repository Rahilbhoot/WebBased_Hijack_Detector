"""Shared data models for normalized events, batches, and security alerts.

Built using Python dataclasses for zero-dependency execution across both AWS Lambda
and native Windows agent environments.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    """Uniform normalized event schema matching PRD Section 9.1."""

    device_id: str
    timestamp: str  # ISO 8601 UTC (e.g. 2026-10-21T10:30:15Z)
    type: str  # process_create, registry_set, file_create, etc.
    source_event_id: int = 0  # Original Windows EventRecordID for deduplication
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    process_image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    user: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value: Optional[str] = None
    file_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the normalized event to a Python dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serializes the normalized event to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NormalizedEvent:
        """Constructs a NormalizedEvent instance from a dictionary."""
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class EventBatch:
    """Batch payload sent from endpoint agent to cloud ingestion API."""

    device_id: str
    agent_version: str = "1.0.0"
    events: List[NormalizedEvent] = field(default_factory=list)


@dataclass
class Alert:
    """Generated detection alert matching PRD Section 9.2."""

    device_id: str
    timestamp: str  # ISO 8601 UTC
    rule_ids: List[str]
    score: int
    severity: str  # Low, Medium, High
    explanation: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mitre_ids: List[str] = field(default_factory=list)
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the alert to a Python dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serializes the alert to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Alert:
        """Constructs an Alert instance from a dictionary."""
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)
