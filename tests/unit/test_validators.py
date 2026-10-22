"""Unit tests for shared cloud payload validation logic."""

from __future__ import annotations

from shared.validators import (
    MAX_BATCH_EVENTS,
    MAX_PAYLOAD_BYTES,
    validate_batch_payload,
    validate_iso_timestamp,
    validate_normalized_event,
    validate_payload_size,
)


def test_validate_payload_size_valid():
    ok, err = validate_payload_size("Hello world")
    assert ok is True
    assert err is None


def test_validate_payload_size_exceeded():
    large_payload = "x" * (MAX_PAYLOAD_BYTES + 10)
    ok, err = validate_payload_size(large_payload)
    assert ok is False
    assert "exceeds limit" in err


def test_validate_iso_timestamp_valid():
    ok, err = validate_iso_timestamp("2026-10-21T10:30:15Z")
    assert ok is True
    assert err is None

    ok2, err2 = validate_iso_timestamp("2026-10-21T10:30:15+00:00")
    assert ok2 is True
    assert err2 is None


def test_validate_iso_timestamp_naive_rejected():
    # Naive timestamp without timezone
    ok, err = validate_iso_timestamp("2026-10-21T10:30:15")
    assert ok is False
    assert "must specify a UTC timezone" in err


def test_validate_iso_timestamp_invalid_format():
    ok, err = validate_iso_timestamp("not-a-timestamp")
    assert ok is False
    assert "Invalid ISO 8601" in err


def test_validate_normalized_event_valid():
    event = {
        "event_id": "123e4567-e89b-12d3-a456-426614174000",
        "device_id": "PC-LAB-01",
        "timestamp": "2026-10-21T10:30:15Z",
        "type": "process_create",
        "process_image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
    }
    ok, err = validate_normalized_event(event)
    assert ok is True
    assert err is None


def test_validate_normalized_event_missing_required():
    event = {
        "event_id": "123e4567-e89b-12d3-a456-426614174000",
        "device_id": "PC-LAB-01",
        # Missing timestamp and type
    }
    ok, err = validate_normalized_event(event)
    assert ok is False
    assert "Missing or empty required event field: 'timestamp'" in err


def test_validate_normalized_event_invalid_type():
    event = {
        "event_id": "123e4567-e89b-12d3-a456-426614174000",
        "device_id": "PC-LAB-01",
        "timestamp": "2026-10-21T10:30:15Z",
        "type": "malicious_unrecognized_type",
    }
    ok, err = validate_normalized_event(event)
    assert ok is False
    assert "Invalid event type" in err


def test_validate_normalized_event_reject_nested_objects():
    # Nested dict should be rejected to protect schema integrity
    event = {
        "event_id": "123e4567-e89b-12d3-a456-426614174000",
        "device_id": "PC-LAB-01",
        "timestamp": "2026-10-21T10:30:15Z",
        "type": "process_create",
        "nested_field": {"evil": True},
    }
    ok, err = validate_normalized_event(event)
    assert ok is False
    assert "nested objects/arrays are not permitted" in err


def test_validate_batch_payload_valid():
    payload = {
        "device_id": "PC-LAB-01",
        "events": [
            {
                "event_id": "123e4567-e89b-12d3-a456-426614174000",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
            }
        ],
    }
    ok, err, events = validate_batch_payload(payload)
    assert ok is True
    assert err is None
    assert len(events) == 1


def test_validate_batch_payload_device_mismatch():
    payload = {
        "device_id": "PC-LAB-01",
        "events": [
            {
                "event_id": "123e4567-e89b-12d3-a456-426614174000",
                "device_id": "SPOOFED-DEVICE-02",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
            }
        ],
    }
    ok, err, events = validate_batch_payload(payload)
    assert ok is False
    assert "does not match batch device_id" in err


def test_validate_batch_payload_exceeding_max_batch():
    events = [
        {
            "event_id": f"event-{i}",
            "device_id": "PC-LAB-01",
            "timestamp": "2026-10-21T10:30:15Z",
            "type": "process_create",
        }
        for i in range(MAX_BATCH_EVENTS + 1)
    ]
    payload = {"device_id": "PC-LAB-01", "events": events}
    ok, err, valid_events = validate_batch_payload(payload)
    assert ok is False
    assert "exceeding max limit" in err


def test_validate_batch_payload_empty_events():
    payload = {"device_id": "PC-LAB-01", "events": []}
    ok, err, events = validate_batch_payload(payload)
    assert ok is False
    assert "Batch must contain at least one event" in err
