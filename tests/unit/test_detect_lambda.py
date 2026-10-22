"""Unit tests for Cloud Detection Lambda."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from detect import (
    handler,
    load_rules_from_s3,
)
from shared.correlator import EventCorrelator
from shared.models import NormalizedEvent
from shared.rule_engine import RuleEngine


@pytest.fixture
def test_detectors():
    """Initializes RuleEngine and EventCorrelator using actual project rule YAML files."""
    rules_path = Path(__file__).resolve().parent.parent.parent / "rules" / "rules.yaml"
    whitelist_path = Path(__file__).resolve().parent.parent.parent / "rules" / "whitelist.yaml"
    corr_path = Path(__file__).resolve().parent.parent.parent / "rules" / "correlation_rules.yaml"

    engine = RuleEngine(rules_path=rules_path, whitelist_path=whitelist_path)
    correlator = EventCorrelator(correlations_path=corr_path)
    return engine, correlator


@pytest.fixture
def mock_cloud_services():
    mock_s3 = MagicMock()
    mock_dyn = MagicMock()
    mock_alerts_table = MagicMock()
    mock_history_table = MagicMock()
    mock_sns = MagicMock()

    def get_table(name):
        if "alerts" in name:
            return mock_alerts_table
        return mock_history_table

    mock_dyn.Table.side_effect = get_table
    # Default: no recent alerts or history
    mock_alerts_table.query.return_value = {"Items": []}
    mock_history_table.query.return_value = {"Items": []}

    return mock_s3, mock_dyn, mock_alerts_table, mock_history_table, mock_sns


def test_detect_bh001_generates_alert(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, _, mock_sns = mock_cloud_services

    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-101",
        "events": [
            {
                "event_id": "ev-bh001",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
                "source_event_id": 100,
                "process_image": "C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe",
                "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
                "parent_image": "C:\\Users\\student\\AppData\\evil.exe",
            }
        ],
    }

    res = handler(
        event_payload,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        sns_client=mock_sns,
        override_engine=engine,
        override_correlator=correlator,
    )

    assert res["status"] == "processed"
    assert res["events_evaluated"] == 1
    assert res["alerts_generated"] == 1
    assert res["high_alerts"] == 0  # Score 40 = Medium

    # Verify alert written to DynamoDB
    mock_alerts_table.put_item.assert_called_once()
    called_item = mock_alerts_table.put_item.call_args[1]["Item"]
    assert "BH001" in called_item["rule_ids"]
    assert called_item["score"] == 40
    assert called_item["severity"] == "Medium"
    assert "T1090" in called_item["mitre_ids"]
    assert "T1176" in called_item["mitre_ids"]

    # Medium alert does not trigger SNS
    mock_sns.publish.assert_not_called()


def test_detect_bh007_generates_high_alert_and_sns(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, _, mock_sns = mock_cloud_services

    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-102",
        "events": [
            {
                "event_id": "ev-bh007",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "log_cleared",
                "source_event_id": 101,
                "user": "LAB\\attacker",
            }
        ],
    }

    import detect

    orig_sns_arn = detect.SNS_TOPIC_ARN
    detect.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:test-topic"

    try:
        res = handler(
            event_payload,
            s3_client=mock_s3,
            dynamodb_resource=mock_dyn,
            sns_client=mock_sns,
            override_engine=engine,
            override_correlator=correlator,
        )

        assert res["status"] == "processed"
        assert res["alerts_generated"] == 1
        assert res["high_alerts"] == 1  # BH007 base_score 60 = High

        # Verify SNS publish was invoked
        mock_sns.publish.assert_called_once()
        publish_kwargs = mock_sns.publish.call_args[1]
        assert "[HIGH] Browser Hijack Alert" in publish_kwargs["Subject"]
        assert "LAB\\attacker" in publish_kwargs["Message"]
        assert "T1070.001" in publish_kwargs["Message"]
    finally:
        detect.SNS_TOPIC_ARN = orig_sns_arn


def test_detect_whitelist_suppression(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, _, mock_sns = mock_cloud_services

    # GoogleUpdate.exe modifying policy is whitelisted in whitelist.yaml
    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-103",
        "events": [
            {
                "event_id": "ev-whitelist",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "registry_set",
                "source_event_id": 102,
                "process_image": "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe",
                "registry_key": "HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
            }
        ],
    }

    res = handler(
        event_payload,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        sns_client=mock_sns,
        override_engine=engine,
        override_correlator=correlator,
    )

    assert res["status"] == "processed"
    assert res["alerts_generated"] == 0
    mock_alerts_table.put_item.assert_not_called()


def test_detect_correlation_cr01_score_boost(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, mock_history_table, mock_sns = mock_cloud_services

    # Mock recent history having BH002 registry modification within 5 minutes
    mock_history_table.query.return_value = {
        "Items": [
            {
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:28:00Z#prev-ev",
                "raw_timestamp": "2026-10-21T10:28:00Z",
                "type": "registry_set",
                "registry_key": "HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
            }
        ]
    }

    # Pre-record BH002 in correlator
    prev_ev = NormalizedEvent(
        event_id="prev-bh002",
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:28:00Z",
        type="registry_set",
        source_event_id=50,
        registry_key="HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
    )
    correlator.record_event("PC-LAB-01", prev_ev, ["BH002"])

    # Current event: BH001 (Chrome launched with proxy flag) 2 minutes later
    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-corr",
        "events": [
            {
                "event_id": "ev-bh001",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:00Z",
                "type": "process_create",
                "source_event_id": 105,
                "process_image": "C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe",
                "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
                "parent_image": "evil.exe",
            }
        ],
    }

    res = handler(
        event_payload,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        sns_client=mock_sns,
        override_engine=engine,
        override_correlator=correlator,
    )

    assert res["status"] == "processed"
    assert res["alerts_generated"] == 1
    called_item = mock_alerts_table.put_item.call_args[1]["Item"]

    # Base score 40 + CR01 correlation bonus 30 = 70
    assert called_item["score"] == 70
    assert called_item["severity"] == "High"
    assert "CR01" in called_item["rule_ids"]
    assert "CR01" in called_item["explanation"]


def test_detect_alert_deduplication(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, _, mock_sns = mock_cloud_services

    # Mock that a matching alert for BH001 was already generated 3 minutes ago
    mock_alerts_table.query.return_value = {
        "Items": [
            {
                "alert_id": "existing-alert-uuid",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:27:00Z",
                "rule_ids": ["BH001"],
                "score": 40,
                "severity": "Medium",
            }
        ]
    }

    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-repeat",
        "events": [
            {
                "event_id": "ev-bh001-repeat",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:00Z",
                "type": "process_create",
                "source_event_id": 110,
                "process_image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
            }
        ],
    }

    res = handler(
        event_payload,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        sns_client=mock_sns,
        override_engine=engine,
        override_correlator=correlator,
    )

    assert res["status"] == "processed"
    # Deduplicated: did not create a new alert record
    assert res["alerts_generated"] == 0
    mock_alerts_table.put_item.assert_not_called()


def test_load_rules_from_s3(mock_cloud_services):
    mock_s3, _, _, _, _ = mock_cloud_services

    sample_rules = (
        "rules:\n"
        "  - id: BH001\n"
        "    name: Test\n"
        "    event_type: process_create\n"
        "    base_score: 10\n"
    )
    sample_whitelist = "trusted_paths:\n  - C:\\Windows\\*\n"
    sample_corr = "correlations:\n  - id: CR01\n    name: TestCorr\n    required_rules: [BH001]\n"

    def mock_get_object(Bucket, Key):
        content = ""
        if "correlation_rules.yaml" in Key:
            content = sample_corr
        elif "whitelist.yaml" in Key:
            content = sample_whitelist
        elif "rules.yaml" in Key:
            content = sample_rules
        return {"Body": io.BytesIO(content.encode("utf-8"))}

    mock_s3.get_object.side_effect = mock_get_object

    engine, correlator = load_rules_from_s3(mock_s3)
    assert len(engine.rules) == 1
    assert engine.rules[0].id == "BH001"
    assert len(correlator.rules) == 1
    assert correlator.rules[0].id == "CR01"


def test_detect_performance_rapid_batch(test_detectors, mock_cloud_services):
    engine, correlator = test_detectors
    mock_s3, mock_dyn, mock_alerts_table, _, mock_sns = mock_cloud_services

    # Generate 50 mixed events
    events = []
    for i in range(50):
        events.append(
            {
                "event_id": f"rapid-ev-{i}",
                "device_id": "PC-LAB-01",
                "timestamp": "2026-10-21T10:30:15Z",
                "type": "process_create",
                "source_event_id": 200 + i,
                "process_image": "C:\\Windows\\System32\\notepad.exe"
                if i % 2 == 0
                else "C:\\Chrome\\chrome.exe",
                "command_line": "--proxy-server=127.0.0.1:9999" if i % 2 != 0 else "notepad.exe",
            }
        )

    event_payload = {
        "device_id": "PC-LAB-01",
        "batch_id": "batch-perf",
        "events": events,
    }

    import time

    start = time.perf_counter()
    res = handler(
        event_payload,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        sns_client=mock_sns,
        override_engine=engine,
        override_correlator=correlator,
    )
    duration = time.perf_counter() - start

    assert res["status"] == "processed"
    assert res["events_evaluated"] == 50
    # Must process fast (well under 500ms target)
    assert duration < 0.50
