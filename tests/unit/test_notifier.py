"""Unit tests for notification formatting, anti-spam throttling, and Telegram dispatch."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from shared.models import Alert
from shared.notifier import (
    format_alert_email,
    format_silence_alert,
    record_notification_sent,
    send_telegram_alert,
    should_throttle_notification,
)


@pytest.fixture
def sample_alert():
    return Alert(
        alert_id="test-alert-123",
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:30:15Z",
        rule_ids=["BH001", "CR01"],
        score=70,
        severity="High",
        explanation=(
            "Browser was launched with suspicious flag (--proxy-server) following policy change."
        ),
        mitre_ids=["T1090", "T1112"],
        raw_event={
            "type": "process_create",
            "process_image": "C:\\Chrome\\chrome.exe",
            "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
            "parent_image": "evil.exe",
            "user": "LAB\\student",
        },
    )


def test_format_alert_email(sample_alert):
    subject, body = format_alert_email(sample_alert, dashboard_url="https://secops.example.com")
    assert "[HIGH] Browser Hijack Alert — PC-LAB-01" in subject
    assert "PC-LAB-01" in body
    assert "Composite Risk Score: 70" in body
    assert "BH001, CR01" in body
    assert "T1090, T1112" in body
    assert "evil.exe" in body
    assert "https://secops.example.com/alerts/test-alert-123" in body


def test_format_silence_alert():
    subject, body = format_silence_alert("PC-LAB-01", "2026-10-21T10:00:00Z", minutes_silent=15)
    assert "[ALERT] Endpoint Silence Detected — PC-LAB-01" in subject
    assert "15 minutes (threshold: 10 minutes)" in body
    assert "Offline" in body


def test_should_throttle_notification_active(sample_alert):
    mock_table = MagicMock()
    # Mock last notification sent 60 seconds ago (well inside 900s window)
    mock_table.get_item.return_value = {
        "Item": {
            "device_id": "PC-LAB-01",
            "last_notifications": {
                "BH001#CR01": time.time() - 60.0,
            },
        }
    }
    throttled = should_throttle_notification(mock_table, "PC-LAB-01", sample_alert.rule_ids)
    assert throttled is True


def test_should_throttle_notification_expired(sample_alert):
    mock_table = MagicMock()
    # Mock last notification sent 1000 seconds ago (outside 900s window)
    mock_table.get_item.return_value = {
        "Item": {
            "device_id": "PC-LAB-01",
            "last_notifications": {
                "BH001#CR01": time.time() - 1000.0,
            },
        }
    }
    throttled = should_throttle_notification(mock_table, "PC-LAB-01", sample_alert.rule_ids)
    assert throttled is False


def test_should_throttle_notification_first_time(sample_alert):
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"device_id": "PC-LAB-01"}}
    throttled = should_throttle_notification(mock_table, "PC-LAB-01", sample_alert.rule_ids)
    assert throttled is False


def test_record_notification_sent(sample_alert):
    mock_table = MagicMock()
    record_notification_sent(mock_table, "PC-LAB-01", sample_alert.rule_ids)
    mock_table.update_item.assert_called_once()
    kwargs = mock_table.update_item.call_args[1]
    assert kwargs["Key"] == {"device_id": "PC-LAB-01"}
    assert "last_notifications" in kwargs["UpdateExpression"]


@patch("urllib.request.urlopen")
def test_send_telegram_alert_success(mock_urlopen, sample_alert):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    success = send_telegram_alert("bot12345:token", "-10012345678", sample_alert)
    assert success is True
    mock_urlopen.assert_called_once()
