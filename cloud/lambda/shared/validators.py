"""Shared validation logic for cloud ingestion and event processing.

Validates payload size, batch counts, normalized schemas, and event field types
according to PRD Section 8.3 and Section 9.1.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

MAX_PAYLOAD_BYTES: int = 256 * 1024  # 256 KB
MAX_BATCH_EVENTS: int = 100

ALLOWED_EVENT_TYPES: Set[str] = {
    "process_create",
    "file_create",
    "registry_add",
    "registry_set",
    "registry_rename",
    "task_create",
    "service_install",
    "log_cleared",
}

ALLOWED_FIELD_TYPES = (str, int, float, bool, type(None))


def validate_payload_size(raw_body: str | bytes) -> Tuple[bool, Optional[str]]:
    """Validates that raw HTTP request body does not exceed max payload size."""
    size = len(raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body)
    if size > MAX_PAYLOAD_BYTES:
        return (
            False,
            f"Payload size ({size} bytes) exceeds limit of {MAX_PAYLOAD_BYTES} bytes.",
        )
    return True, None


def validate_iso_timestamp(timestamp_str: Any) -> Tuple[bool, Optional[str]]:
    """Validates that timestamp is a non-empty ISO 8601 UTC string."""
    if not isinstance(timestamp_str, str) or not timestamp_str.strip():
        return False, "Timestamp must be a non-empty string."

    ts = timestamp_str.strip()
    try:
        # Standard ISO 8601 parsing
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            return False, "Timestamp must specify a UTC timezone (e.g., Z or +00:00)."
        return True, None
    except ValueError as e:
        return False, f"Invalid ISO 8601 timestamp format: {e}"


def validate_normalized_event(event: Any) -> Tuple[bool, Optional[str]]:
    """Validates a single event dictionary against the normalized event schema."""
    if not isinstance(event, dict):
        return False, "Event must be a JSON object."

    # Required fields
    required_fields = ["event_id", "device_id", "timestamp", "type"]
    for field in required_fields:
        val = event.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            return False, f"Missing or empty required event field: '{field}'."

    # Validate type
    event_type = event.get("type")
    if event_type not in ALLOWED_EVENT_TYPES:
        return (
            False,
            f"Invalid event type '{event_type}'. Allowed types: {sorted(ALLOWED_EVENT_TYPES)}.",
        )

    # Validate timestamp
    valid_ts, ts_err = validate_iso_timestamp(event.get("timestamp"))
    if not valid_ts:
        return False, f"Event '{event.get('event_id')}': {ts_err}"

    # Verify no complex/nested objects in event fields to prevent injection
    for key, val in event.items():
        if not isinstance(val, ALLOWED_FIELD_TYPES):
            return (
                False,
                f"Invalid field value for '{key}': nested objects/arrays are not permitted.",
            )

    return True, None


def validate_batch_payload(payload: Any) -> Tuple[bool, Optional[str], List[Dict[str, Any]]]:
    """Validates the entire batch ingestion payload.

    Returns:
        (is_valid, error_message, validated_events_list)
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a JSON object.", []

    device_id = payload.get("device_id")
    if not device_id or not isinstance(device_id, str) or not device_id.strip():
        return False, "Missing or invalid required batch field: 'device_id'.", []

    events = payload.get("events")
    if events is None or not isinstance(events, list):
        return False, "Missing or invalid required batch field: 'events' (must be a list).", []

    if len(events) == 0:
        return False, "Batch must contain at least one event.", []

    if len(events) > MAX_BATCH_EVENTS:
        return (
            False,
            f"Batch contains {len(events)} events, exceeding max limit of {MAX_BATCH_EVENTS}.",
            [],
        )

    validated_events: List[Dict[str, Any]] = []
    for idx, ev in enumerate(events):
        valid, err = validate_normalized_event(ev)
        if not valid:
            return False, f"Event at index {idx} failed validation: {err}", []

        # Ensure event device_id matches batch device_id
        if ev.get("device_id") != device_id:
            return (
                False,
                f"Event at index {idx} device_id '{ev.get('device_id')}' does not match "
                f"batch device_id '{device_id}'.",
                [],
            )

        validated_events.append(ev)

    return True, None, validated_events
