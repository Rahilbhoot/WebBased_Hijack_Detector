"""Unit tests for Cloud Ingest Lambda."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from ingest import (
    generate_s3_key,
    handler,
    record_event_history,
)


@pytest.fixture
def mock_aws_clients():
    mock_s3 = MagicMock()
    mock_dyn = MagicMock()
    mock_history_table = MagicMock()
    mock_dyn.Table.return_value = mock_history_table
    mock_lambda = MagicMock()
    return mock_s3, mock_dyn, mock_history_table, mock_lambda


def test_generate_s3_key_format():
    dt = datetime(2026, 10, 21, 14, 30, 45, tzinfo=timezone.utc)
    key = generate_s3_key("PC-LAB-01", now=dt)
    assert key.startswith("PC-LAB-01/2026/10/21/14-30-45-")
    assert key.endswith(".json")


def test_record_event_history_new_event(mock_aws_clients):
    _, _, mock_table, _ = mock_aws_clients
    event = {
        "event_id": "ev-100",
        "device_id": "PC-LAB-01",
        "timestamp": "2026-10-21T10:30:15Z",
        "type": "process_create",
    }
    is_new = record_event_history(mock_table, "PC-LAB-01", event)
    assert is_new is True
    mock_table.put_item.assert_called_once()


def test_record_event_history_duplicate(mock_aws_clients):
    _, _, mock_table, _ = mock_aws_clients
    mock_table.put_item.side_effect = ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "Conditional check failed",
            }
        },
        "PutItem",
    )
    event = {
        "event_id": "ev-duplicate",
        "device_id": "PC-LAB-01",
        "timestamp": "2026-10-21T10:30:15Z",
        "type": "process_create",
    }
    is_new = record_event_history(mock_table, "PC-LAB-01", event)
    assert is_new is False


def test_ingest_payload_too_large(mock_aws_clients):
    mock_s3, mock_dyn, _, mock_lambda = mock_aws_clients
    huge_body = "x" * (300 * 1024)
    event = {"body": huge_body}

    resp = handler(event, s3_client=mock_s3, dynamodb_resource=mock_dyn, lambda_client=mock_lambda)
    assert resp["statusCode"] == 413
    assert "Payload Too Large" in resp["body"]


def test_ingest_malformed_json(mock_aws_clients):
    mock_s3, mock_dyn, _, mock_lambda = mock_aws_clients
    event = {"body": "{not valid json"}

    resp = handler(event, s3_client=mock_s3, dynamodb_resource=mock_dyn, lambda_client=mock_lambda)
    assert resp["statusCode"] == 400
    assert "Invalid JSON format" in resp["body"]


def test_ingest_device_spoofing_forbidden(mock_aws_clients):
    mock_s3, mock_dyn, _, mock_lambda = mock_aws_clients
    body = {
        "device_id": "ATTACKER-DEVICE",
        "events": [
            {
                "event_id": "123e4567-e89b-12d3-a456-426614174000",
                "device_id": "ATTACKER-DEVICE",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
            }
        ],
    }
    event = {
        "body": json.dumps(body),
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "deviceId": "LEGIT-DEVICE-01",
                }
            }
        },
    }

    resp = handler(event, s3_client=mock_s3, dynamodb_resource=mock_dyn, lambda_client=mock_lambda)
    assert resp["statusCode"] == 403
    assert "Device ID does not match" in resp["body"]


def test_ingest_successful_batch_flow(mock_aws_clients):
    mock_s3, mock_dyn, mock_table, mock_lambda = mock_aws_clients

    # 2 events in batch: 1 new, 1 duplicate
    def mock_put_item(*args, **kwargs):
        item = kwargs.get("Item", {})
        if item.get("event_id") == "duplicate-event-id":
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        return {}

    mock_table.put_item.side_effect = mock_put_item

    payload = {
        "device_id": "PC-LAB-01",
        "events": [
            {
                "event_id": "new-event-id-1",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
                "process_image": "chrome.exe",
            },
            {
                "event_id": "duplicate-event-id",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
                "process_image": "chrome.exe",
            },
        ],
    }

    event = {
        "body": json.dumps(payload),
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "deviceId": "PC-LAB-01",
                }
            }
        },
    }

    resp = handler(event, s3_client=mock_s3, dynamodb_resource=mock_dyn, lambda_client=mock_lambda)
    assert resp["statusCode"] == 202
    body = json.loads(resp["body"])
    assert body["status"] == "accepted"
    assert body["accepted_count"] == 1
    assert body["duplicate_count"] == 1
    assert "s3_key" in body

    # Verify S3 archive called
    mock_s3.put_object.assert_called_once()
    # Verify Detect Lambda invoked for accepted events
    mock_lambda.invoke.assert_called_once()


def test_ingest_base64_encoded_payload(mock_aws_clients):
    mock_s3, mock_dyn, mock_table, mock_lambda = mock_aws_clients

    payload = {
        "device_id": "PC-LAB-01",
        "events": [
            {
                "event_id": "b64-ev-1",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
            }
        ],
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    event = {
        "body": encoded,
        "isBase64Encoded": True,
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "deviceId": "PC-LAB-01",
                }
            }
        },
    }

    resp = handler(event, s3_client=mock_s3, dynamodb_resource=mock_dyn, lambda_client=mock_lambda)
    assert resp["statusCode"] == 202
    body = json.loads(resp["body"])
    assert body["accepted_count"] == 1
