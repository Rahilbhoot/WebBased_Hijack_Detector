"""Integration tests for endpoint heartbeat reporting, silence detection, and key lifecycle."""

import hashlib
import json
import time
from unittest.mock import MagicMock, patch

from api_devices import handler as devices_handler
from authorizer import handler as authorizer_handler
from heartbeat import handler as heartbeat_handler


def test_heartbeat_updates_metadata_and_last_seen():
    """Verify heartbeat updates last_seen and forensic metadata in DynamoDB."""
    mock_table = MagicMock()
    mock_sns = MagicMock()
    mock_dyn = MagicMock()
    mock_dyn.Table.return_value = mock_table

    event = {
        "body": json.dumps({
            "device_id": "PC-TEST-01",
            "agent_version": "1.0.0",
            "uptime_seconds": 3600,
            "os_version": "Windows 11 Pro 23H2",
            "hostname": "DESKTOP-TEST-01",
            "event_queue_size": 3,
            "total_events_sent": 250,
            "ip_address": "10.0.0.45",
        }),
        "requestContext": {
            "http": {"sourceIp": "192.168.1.100"},
            "authorizer": {"lambda": {"deviceId": "PC-TEST-01"}},
        },
    }

    resp = heartbeat_handler(event, dynamodb_resource=mock_dyn, sns_client=mock_sns)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "recorded"
    assert body["device_id"] == "PC-TEST-01"

    # Verify update_item called with enriched metadata
    mock_table.update_item.assert_called_once()
    _, kwargs = mock_table.update_item.call_args
    assert kwargs["Key"] == {"device_id": "PC-TEST-01"}
    vals = kwargs["ExpressionAttributeValues"]
    assert vals[":ver"] == "1.0.0"
    assert vals[":uptime"] == 3600
    assert vals[":os"] == "Windows 11 Pro 23H2"
    assert vals[":qs"] == 3
    assert vals[":host"] == "DESKTOP-TEST-01"
    assert vals[":tot"] == 250
    assert vals[":ip"] == "192.168.1.100"


def test_silence_scanner_detects_offline_device_and_alerts():
    """Verify silence scanner marks device Offline after >10 min silence and alerts via SNS."""
    mock_table = MagicMock()
    mock_sns = MagicMock()
    mock_dyn = MagicMock()
    mock_dyn.Table.return_value = mock_table

    now_epoch = int(time.time())

    # Device A: Active 2 min ago (Online)
    # Device B: Active 15 min ago (Online -> should become Offline)
    # Device C: Already Offline (should be skipped)
    mock_table.scan.return_value = {
        "Items": [
            {
                "device_id": "PC-ACTIVE",
                "status": "Online",
                "last_seen_epoch": now_epoch - 120,
                "last_seen": "2026-10-22T10:00:00Z",
            },
            {
                "device_id": "PC-SILENT",
                "status": "Online",
                "last_seen_epoch": now_epoch - 900,  # 15 min ago
                "last_seen": "2026-10-22T09:47:00Z",
            },
            {
                "device_id": "PC-ALREADY-OFFLINE",
                "status": "Offline",
                "last_seen_epoch": now_epoch - 1800,
                "last_seen": "2026-10-22T09:30:00Z",
            },
        ]
    }

    scheduled_event = {
        "source": "aws.events",
        "detail-type": "Scheduled Event",
        "time": "2026-10-22T10:05:00Z",
        "resources": ["arn:aws:events:us-east-1:123456789012:rule/silence-checker"],
    }

    with patch("heartbeat.SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-alerts"):
        result = heartbeat_handler(scheduled_event, dynamodb_resource=mock_dyn, sns_client=mock_sns)

    assert result["status"] == "checked"
    assert result["scanned_count"] == 3
    assert result["silent_count"] == 1
    assert "PC-SILENT" in result["silent_devices"]

    # Verify status changed to Offline for PC-SILENT
    mock_table.update_item.assert_called_once()
    _, kwargs = mock_table.update_item.call_args
    assert kwargs["Key"] == {"device_id": "PC-SILENT"}
    assert kwargs["ExpressionAttributeValues"][":offline"] == "Offline"

    # Verify SNS silence notification sent
    mock_sns.publish.assert_called_once()
    _, sns_kwargs = mock_sns.publish.call_args
    assert "PC-SILENT" in sns_kwargs["Subject"]


def test_revoked_device_key_rejection_at_authorizer():
    """Verify device with revoked key is rejected by Lambda authorizer with Deny policy."""
    mock_table = MagicMock()
    mock_dyn = MagicMock()
    mock_dyn.Table.return_value = mock_table

    test_key = "bh_revoked_key_test_1234567890"
    key_hash = hashlib.sha256(test_key.encode("utf-8")).hexdigest()

    mock_table.query.return_value = {
        "Items": [
            {
                "device_id": "PC-REVOKED",
                "api_key_hash": key_hash,
                "status": "Revoked",
            }
        ]
    }

    event = {
        "headers": {"x-api-key": test_key},
        "routeArn": "arn:aws:execute-api:us-east-1:123456789012:xyz/dev/POST/heartbeat",
    }

    policy = authorizer_handler(event, dynamodb_resource=mock_dyn)
    assert policy["isAuthorized"] is False


def test_device_onboarding_and_key_rotation():
    """Verify new device onboarding produces one-time API key and key rotation generates a new key.
    """
    mock_table = MagicMock()
    mock_dyn = MagicMock()
    mock_dyn.Table.return_value = mock_table

    # 1. Onboard initial endpoint
    event_onboard = {
        "routeKey": "POST /devices",
        "body": json.dumps({"device_id": "PC-FINANCE-01", "hostname": "PC-FINANCE-01"}),
    }
    resp1 = devices_handler(event_onboard, dynamodb_resource=mock_dyn)
    assert resp1["statusCode"] == 201
    body1 = json.loads(resp1["body"])
    initial_key = body1["api_key"]
    assert len(initial_key) == 64
    assert body1["device_id"] == "PC-FINANCE-01"

    # 2. Rotate key for same endpoint
    event_rotate = {
        "routeKey": "POST /devices",
        "body": json.dumps({"device_id": "PC-FINANCE-01", "hostname": "PC-FINANCE-01"}),
    }
    resp2 = devices_handler(event_rotate, dynamodb_resource=mock_dyn)
    assert resp2["statusCode"] == 201
    body2 = json.loads(resp2["body"])
    new_key = body2["api_key"]

    assert len(new_key) == 64
    assert new_key != initial_key  # New rotated credential
