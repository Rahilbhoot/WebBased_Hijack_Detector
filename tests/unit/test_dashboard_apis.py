"""Unit tests for Dashboard APIs: alerts, devices, stats, rules."""

from __future__ import annotations

import io
from unittest.mock import MagicMock

import pytest
from api_alerts import get_alert_detail, list_alerts
from api_devices import list_devices, register_device, revoke_device_key
from api_rules import load_catalog
from api_stats import aggregate_stats


@pytest.fixture
def mock_dyn_tables():
    mock_dyn = MagicMock()
    mock_alerts = MagicMock()
    mock_devices = MagicMock()
    mock_history = MagicMock()

    def get_table(name):
        if "alert" in name:
            return mock_alerts
        elif "device" in name:
            return mock_devices
        return mock_history

    mock_dyn.Table.side_effect = get_table
    return mock_dyn, mock_alerts, mock_devices, mock_history


# --- Alerts API Tests ---
def test_list_alerts_device_filter(mock_dyn_tables):
    _, mock_alerts, _, _ = mock_dyn_tables
    mock_alerts.query.return_value = {
        "Items": [{"alert_id": "a1", "device_id": "PC-LAB-01", "severity": "High", "score": 70}]
    }
    res = list_alerts(mock_alerts, device_id="PC-LAB-01")
    assert res["count"] == 1
    assert res["alerts"][0]["device_id"] == "PC-LAB-01"


def test_list_alerts_severity_filter(mock_dyn_tables):
    _, mock_alerts, _, _ = mock_dyn_tables
    mock_alerts.query.return_value = {
        "Items": [{"alert_id": "a2", "device_id": "PC-LAB-02", "severity": "High", "score": 60}]
    }
    res = list_alerts(mock_alerts, severity="High")
    assert res["count"] == 1
    assert res["alerts"][0]["severity"] == "High"


def test_get_alert_detail_not_found(mock_dyn_tables):
    _, mock_alerts, _, mock_history = mock_dyn_tables
    mock_alerts.scan.return_value = {"Items": []}
    res = get_alert_detail(mock_alerts, mock_history, "non-existent-alert")
    assert res["status_code"] == 404


def test_get_alert_detail_success(mock_dyn_tables):
    _, mock_alerts, _, mock_history = mock_dyn_tables
    mock_alerts.scan.return_value = {
        "Items": [
            {
                "alert_id": "a-100",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "severity": "High",
            }
        ]
    }
    mock_history.query.return_value = {"Items": [{"event_id": "ev-rel", "type": "process_create"}]}
    res = get_alert_detail(mock_alerts, mock_history, "a-100")
    assert res["status_code"] == 200
    assert res["alert"]["alert_id"] == "a-100"
    assert len(res["timeline"]) == 1


# --- Devices API Tests ---
def test_list_devices(mock_dyn_tables):
    _, _, mock_devices, _ = mock_dyn_tables
    mock_devices.scan.return_value = {
        "Items": [
            {"device_id": "PC-01", "status": "Online"},
            {"device_id": "PC-02", "status": "Offline"},
        ]
    }
    res = list_devices(mock_devices)
    assert res["count"] == 2
    assert res["devices"][0]["device_id"] == "PC-01"


def test_register_device_generates_api_key(mock_dyn_tables):
    _, _, mock_devices, _ = mock_dyn_tables
    payload = {"device_id": "PC-NEW-01", "hostname": "lab-pc-new"}
    res = register_device(mock_devices, payload)
    assert res["status_code"] == 201
    assert res["device_id"] == "PC-NEW-01"
    assert "api_key" in res
    assert len(res["api_key"]) == 64  # 32 bytes hex = 64 characters
    mock_devices.put_item.assert_called_once()
    saved_item = mock_devices.put_item.call_args[1]["Item"]
    assert saved_item["device_id"] == "PC-NEW-01"
    assert "api_key_hash" in saved_item


def test_revoke_device_key(mock_dyn_tables):
    _, _, mock_devices, _ = mock_dyn_tables
    res = revoke_device_key(mock_devices, "PC-01")
    assert res["status_code"] == 200
    assert res["status"] == "Revoked"
    mock_devices.update_item.assert_called_once()


# --- Stats API Tests ---
def test_aggregate_stats(mock_dyn_tables):
    _, mock_alerts, mock_devices, _ = mock_dyn_tables
    mock_alerts.scan.return_value = {
        "Items": [
            {
                "severity": "High",
                "rule_ids": ["BH001", "CR01"],
                "timestamp": "2026-10-21T10:00:00Z",
            },
            {
                "severity": "Medium",
                "rule_ids": ["BH003"],
                "timestamp": "2026-10-21T11:00:00Z",
            },
        ]
    }
    mock_devices.scan.return_value = {
        "Items": [
            {"device_id": "PC-01", "status": "Online"},
            {"device_id": "PC-02", "status": "Offline"},
        ]
    }
    stats = aggregate_stats(mock_alerts, mock_devices)
    assert stats["total_alerts_24h"] == 2
    assert stats["severity_distribution"]["High"] == 1
    assert stats["severity_distribution"]["Medium"] == 1
    assert stats["fleet_status"]["online"] == 1
    assert stats["fleet_status"]["offline"] == 1
    assert len(stats["top_rules"]) >= 1


# --- Rules API Tests ---
def test_load_catalog():
    mock_s3 = MagicMock()

    def mock_get(Bucket, Key):
        if "correlation" in Key:
            return {"Body": io.BytesIO(b"correlations:\n  - id: CR01\n")}
        elif "whitelist" in Key:
            return {"Body": io.BytesIO(b"trusted_paths: ['C:\\\\Windows\\\\*']")}
        return {"Body": io.BytesIO(b"rules:\n  - id: BH001\n    name: Test Rule\n")}

    mock_s3.get_object.side_effect = mock_get
    cat = load_catalog(mock_s3)
    assert len(cat["rules"]) == 1
    assert cat["rules"][0]["id"] == "BH001"
    assert len(cat["correlations"]) == 1
