"""Unit tests for Heartbeat & Silence Alerting Lambda."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from heartbeat import (
    check_silent_devices,
    handle_heartbeat_post,
    handler,
)


@pytest.fixture
def mock_cloud_services():
    mock_dyn = MagicMock()
    mock_table = MagicMock()
    mock_dyn.Table.return_value = mock_table
    mock_sns = MagicMock()
    return mock_dyn, mock_table, mock_sns


def test_heartbeat_missing_device_id(mock_cloud_services):
    _, mock_table, _ = mock_cloud_services
    event = {"body": json.dumps({"agent_version": "1.0.0"})}

    resp = handle_heartbeat_post(event, mock_table)
    assert resp["statusCode"] == 400
    assert "Missing required field: 'device_id'" in resp["body"]


def test_heartbeat_device_spoofing_forbidden(mock_cloud_services):
    _, mock_table, _ = mock_cloud_services
    event = {
        "body": json.dumps({"device_id": "SPOOFED-DEVICE"}),
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "deviceId": "LEGIT-DEVICE",
                }
            }
        },
    }

    resp = handle_heartbeat_post(event, mock_table)
    assert resp["statusCode"] == 403
    assert "Device ID mismatch" in resp["body"]


def test_heartbeat_successful_post(mock_cloud_services):
    _, mock_table, _ = mock_cloud_services
    event = {
        "body": json.dumps(
            {
                "device_id": "PC-LAB-01",
                "agent_version": "1.0.0",
                "uptime_seconds": 7200,
                "os_version": "Windows 11 Pro",
                "event_queue_size": 2,
            }
        ),
        "requestContext": {
            "authorizer": {
                "lambda": {
                    "deviceId": "PC-LAB-01",
                }
            }
        },
    }

    resp = handle_heartbeat_post(event, mock_table)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "recorded"
    assert body["device_id"] == "PC-LAB-01"

    # Verify DynamoDB update
    mock_table.update_item.assert_called_once()
    kwargs = mock_table.update_item.call_args[1]
    assert kwargs["Key"] == {"device_id": "PC-LAB-01"}
    assert kwargs["ExpressionAttributeValues"][":online"] == "Online"
    assert kwargs["ExpressionAttributeValues"][":uptime"] == 7200


def test_silence_check_active_device_stays_online(mock_cloud_services):
    _, mock_table, mock_sns = mock_cloud_services
    now = time.time()
    # Device sent heartbeat 2 minutes ago
    mock_table.scan.return_value = {
        "Items": [
            {
                "device_id": "PC-ACTIVE-01",
                "status": "Online",
                "last_seen_epoch": int(now - 120),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }

    res = check_silent_devices(mock_table, mock_sns)
    assert res["status"] == "checked"
    assert res["silent_count"] == 0
    mock_table.update_item.assert_not_called()
    mock_sns.publish.assert_not_called()


def test_silence_check_silent_device_alert(mock_cloud_services):
    _, mock_table, mock_sns = mock_cloud_services
    now = time.time()

    import heartbeat

    orig_arn = heartbeat.SNS_TOPIC_ARN
    heartbeat.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:test-topic"

    try:
        # Device silent for 15 minutes (900 seconds > 600 threshold)
        mock_table.scan.return_value = {
            "Items": [
                {
                    "device_id": "PC-SILENT-01",
                    "status": "Online",
                    "last_seen_epoch": int(now - 900),
                    "last_seen": "2026-10-21T10:15:00Z",
                }
            ]
        }

        res = check_silent_devices(mock_table, mock_sns)
        assert res["status"] == "checked"
        assert res["silent_count"] == 1
        assert "PC-SILENT-01" in res["silent_devices"]

        # Verify device marked Offline
        mock_table.update_item.assert_called_once()
        kwargs = mock_table.update_item.call_args[1]
        assert kwargs["Key"] == {"device_id": "PC-SILENT-01"}
        assert kwargs["ExpressionAttributeValues"][":offline"] == "Offline"

        # Verify SNS silence alert published
        mock_sns.publish.assert_called_once()
        pub_kwargs = mock_sns.publish.call_args[1]
        assert "[ALERT] Endpoint Silence Detected — PC-SILENT-01" in pub_kwargs["Subject"]
        assert "15 minutes" in pub_kwargs["Message"]
    finally:
        heartbeat.SNS_TOPIC_ARN = orig_arn


def test_silence_check_already_offline_device_ignored(mock_cloud_services):
    _, mock_table, mock_sns = mock_cloud_services
    now = time.time()
    mock_table.scan.return_value = {
        "Items": [
            {
                "device_id": "PC-OFFLINE-ALREADY",
                "status": "Offline",
                "last_seen_epoch": int(now - 3600),
                "last_seen": "2026-10-21T09:00:00Z",
            }
        ]
    }

    res = check_silent_devices(mock_table, mock_sns)
    assert res["status"] == "checked"
    assert res["silent_count"] == 0
    mock_table.update_item.assert_not_called()
    mock_sns.publish.assert_not_called()


def test_handler_routes_eventbridge_event(mock_cloud_services):
    mock_dyn, mock_table, mock_sns = mock_cloud_services
    mock_table.scan.return_value = {"Items": []}

    event = {
        "source": "aws.events",
        "detail-type": "Scheduled Event",
    }
    res = handler(event, dynamodb_resource=mock_dyn, sns_client=mock_sns)
    assert res["status"] == "checked"
    mock_table.scan.assert_called_once()
