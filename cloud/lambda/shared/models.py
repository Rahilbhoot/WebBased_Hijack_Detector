"""Shared data models for normalized events, batches, and security alerts."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    """Uniform normalized event schema matching PRD Section 9.1."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    timestamp: str  # ISO 8601 UTC (e.g. 2026-10-21T10:30:15Z)
    type: str  # process_create, registry_set, file_create, etc.
    source_event_id: int  # Original Windows EventRecordID for deduplication
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
        return self.model_dump()

    def to_json(self) -> str:
        """Serializes the normalized event to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NormalizedEvent:
        """Constructs a NormalizedEvent instance from a dictionary."""
        return cls(**data)


class EventBatch(BaseModel):
    """Batch payload sent from endpoint agent to cloud ingestion API."""

    device_id: str
    agent_version: str = "1.0.0"
    events: List[NormalizedEvent] = Field(default_factory=list)


class Alert(BaseModel):
    """Generated detection alert matching PRD Section 9.2."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    timestamp: str  # ISO 8601 UTC
    rule_ids: List[str]
    score: int
    severity: str  # Low, Medium, High
    explanation: str
    mitre_ids: List[str] = Field(default_factory=list)
    raw_event: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the alert to a Python dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Serializes the alert to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Alert:
        """Constructs an Alert instance from a dictionary."""
        return cls(**data)
