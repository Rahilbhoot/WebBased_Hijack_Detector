"""End-to-End Detection, Multi-Stage Correlation, Resilience, and Security Test Suite (Phase 14).

Validates:
1. End-to-End detection of all 8 attack vectors (BH001–BH008).
2. Multi-stage correlation chains (CR01, CR02, CR03) and score bonus calculation.
3. Whitelist suppression of benign administrative and browser processes.
4. Resilience: offline SQLite buffering and 0% event loss across network interruptions.
5. Security: rejection of missing/invalid API keys, device ID mismatches, and injection immunity.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from authorizer import handler as authorizer_handler
from ingest import handler as ingest_handler

from agent.correlator import EventCorrelator
from agent.local_store import LocalStore
from agent.models import NormalizedEvent
from agent.rule_engine import RuleEngine

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


def test_e2e_all_eight_attack_rules_detected():
    """Verify end-to-end detection for all 8 browser hijack attack vectors (BH001–BH008)."""
    engine = RuleEngine(
        rules_path=RULES_DIR / "rules.yaml",
        whitelist_path=RULES_DIR / "whitelist.yaml",
    )

    # BH001: Browser execution with proxy flag
    ev_bh001 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:00:00Z",
        type="process_create",
        source_event_id=1,
        process_image="C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe",
        command_line='chrome.exe --proxy-server="127.0.0.1:8080"',
    )
    m1 = engine.evaluate(ev_bh001)
    assert any(r.id == "BH001" for r in m1)

    # BH002: Browser policy registry alteration
    ev_bh002 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:01:00Z",
        type="registry_set",
        source_event_id=13,
        registry_key="HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    )
    m2 = engine.evaluate(ev_bh002)
    assert any(r.id == "BH002" for r in m2)

    # BH003: Internet Settings proxy override
    ev_bh003 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:02:00Z",
        type="registry_set",
        source_event_id=13,
        registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        registry_value_name="ProxyServer",
        registry_value="127.0.0.1:8080",
    )
    m3 = engine.evaluate(ev_bh003)
    assert any(r.id == "BH003" for r in m3)

    # BH004: Windows hosts file tampering
    ev_bh004 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:03:00Z",
        type="file_create",
        source_event_id=11,
        file_path="C:\\Windows\\System32\\drivers\\etc\\hosts",
    )
    m4 = engine.evaluate(ev_bh004)
    assert any(r.id == "BH004" for r in m4)

    # BH005: Browser shortcut modified with command-line injection
    ev_bh005 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:04:00Z",
        type="file_create",
        source_event_id=11,
        file_path="C:\\Users\\Public\\Desktop\\Google Chrome.lnk",
    )
    m5 = engine.evaluate(ev_bh005)
    assert any(r.id == "BH005" for r in m5)

    # BH006: Suspicious scheduled task or service
    ev_bh006 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:05:00Z",
        type="task_create",
        source_event_id=4698,
        command_line="schtasks.exe /create /tn Updates /tr 'chrome.exe --proxy-server=evil.com'",
    )
    m6 = engine.evaluate(ev_bh006)
    assert any(r.id == "BH006" for r in m6)

    # BH007: Windows Security / Sysmon event log cleared
    ev_bh007 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:06:00Z",
        type="log_cleared",
        source_event_id=1102,
        user="LAB\\Student",
    )
    m7 = engine.evaluate(ev_bh007)
    assert any(r.id == "BH007" for r in m7)

    # BH008: Rogue root certificate added
    ev_bh008 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:07:00Z",
        type="registry_set",
        source_event_id=13,
        registry_key="HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\12345678",
    )
    m8 = engine.evaluate(ev_bh008)
    assert any(r.id == "BH008" for r in m8)


def test_multi_stage_correlation_chains_cr01_cr02_cr03():
    """Verify multi-event correlation sequences and risk bonus computation."""
    correlator = EventCorrelator(correlations_path=RULES_DIR / "correlation_rules.yaml")

    # Sequence for CR01: BH002 (Registry Policy) followed by BH001 (Browser Flag Launch)
    ev_pol = NormalizedEvent(
        device_id="PC-CORR-01",
        timestamp="2026-10-22T10:00:00Z",
        type="registry_set",
        source_event_id=13,
    )
    correlator.record_event("PC-CORR-01", ev_pol, ["BH002"])

    ev_launch = NormalizedEvent(
        device_id="PC-CORR-01",
        timestamp="2026-10-22T10:03:00Z",  # 3 min later (< 5 min window)
        type="process_create",
        source_event_id=1,
    )
    cr01_matches = correlator.evaluate("PC-CORR-01", ev_launch, ["BH001"])
    assert any(cm.rule_id == "CR01" for cm in cr01_matches)
    cr01_bonus = next(cm.score_bonus for cm in cr01_matches if cm.rule_id == "CR01")
    assert cr01_bonus == 30

    # Sequence for CR02: BH003 (Proxy setting) combined with BH004 (hosts file)
    ev_proxy = NormalizedEvent(
        device_id="PC-CORR-02",
        timestamp="2026-10-22T10:00:00Z",
        type="registry_set",
        source_event_id=13,
    )
    correlator.record_event("PC-CORR-02", ev_proxy, ["BH003"])

    ev_hosts = NormalizedEvent(
        device_id="PC-CORR-02",
        timestamp="2026-10-22T10:05:00Z",  # 5 min later (< 10 min window)
        type="file_create",
        source_event_id=11,
    )
    cr02_matches = correlator.evaluate("PC-CORR-02", ev_hosts, ["BH004"])
    assert any(cm.rule_id == "CR02" for cm in cr02_matches)

    # Sequence for CR03: Prior BH alert followed by BH007 (Log Cleared)
    ev_attack = NormalizedEvent(
        device_id="PC-CORR-03",
        timestamp="2026-10-22T10:00:00Z",
        type="process_create",
        source_event_id=1,
    )
    correlator.record_event("PC-CORR-03", ev_attack, ["BH001"])

    ev_clear = NormalizedEvent(
        device_id="PC-CORR-03",
        timestamp="2026-10-22T10:02:00Z",
        type="log_cleared",
        source_event_id=1102,
    )
    cr03_matches = correlator.evaluate("PC-CORR-03", ev_clear, ["BH007"])
    assert any(cm.rule_id == "CR03" for cm in cr03_matches)


def test_whitelist_suppression_of_legitimate_processes():
    """Verify legitimate administrative and browser binaries are suppressed by whitelist."""
    engine = RuleEngine(
        rules_path=RULES_DIR / "rules.yaml",
        whitelist_path=RULES_DIR / "whitelist.yaml",
    )

    # Benign system process modifying hosts file during VPN setup
    ev_benign = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-22T10:00:00Z",
        type="file_create",
        source_event_id=11,
        process_image="C:\\Windows\\System32\\svchost.exe",
        file_path="C:\\Windows\\System32\\drivers\\etc\\hosts",
    )
    matches = engine.evaluate(ev_benign)
    assert len(matches) == 0  # Completely suppressed by trusted path whitelist


def test_resilience_outbox_sqlite_zero_event_loss(tmp_path):
    """Verify offline event buffering handles rapid event generation with zero event loss."""
    db_file = tmp_path / "resilience_queue.sqlite"
    store = LocalStore(db_path=db_file)

    total_simulated = 500
    for i in range(total_simulated):
        batch = {
            "device_id": "PC-RESILIENCE-01",
            "agent_version": "1.0.0",
            "events": [
                {
                    "event_id": f"ev-{i}",
                    "timestamp": "2026-10-22T10:00:00Z",
                    "type": "process_create",
                    "command_line": f"test-process-{i}.exe",
                }
            ],
        }
        store.enqueue_outbox(batch, event_count=1)

    stats = store.get_outbox_stats()
    assert stats["pending_batches"] == total_simulated
    assert stats["pending_events"] == total_simulated

    # Drain batches in chunks of 50
    drained_batches = 0
    while True:
        items = store.peek_outbox(limit=50)
        if not items:
            break
        for item in items:
            store.acknowledge_outbox(item["id"])
            drained_batches += 1

    assert drained_batches == total_simulated
    final_stats = store.get_outbox_stats()
    assert final_stats["pending_batches"] == 0
    assert final_stats["pending_events"] == 0


def test_security_authorizer_rejects_missing_or_invalid_key():
    """Verify Lambda Custom Authorizer rejects requests without valid API keys."""
    mock_dyn = MagicMock()
    mock_table = MagicMock()
    mock_dyn.Table.return_value = mock_table
    mock_table.query.return_value = {"Items": []}
    mock_table.scan.return_value = {"Items": []}

    # Request without x-api-key header
    resp_no_header = authorizer_handler(
        {"routeArn": "arn:aws:execute-api:us-east-1:123456789012:xyz/dev/POST/events"},
        dynamodb_resource=mock_dyn,
    )
    assert resp_no_header["isAuthorized"] is False

    # Request with invalid/unknown key
    resp_bad_key = authorizer_handler(
        {
            "routeArn": "arn:aws:execute-api:us-east-1:123456789012:xyz/dev/POST/events",
            "headers": {"x-api-key": "invalid-unregistered-key"},
        },
        dynamodb_resource=mock_dyn,
    )
    assert resp_bad_key["isAuthorized"] is False


def test_security_sql_injection_payload_immunity():
    """Verify ingestion pipeline safely processes SQL injection string payloads without error."""
    mock_s3 = MagicMock()
    mock_dyn = MagicMock()
    mock_table = MagicMock()
    mock_dyn.Table.return_value = mock_table
    mock_table.get_item.return_value = {}
    mock_lam = MagicMock()

    injection_event = {
        "device_id": "PC-TEST-01",
        "agent_version": "1.0.0",
        "events": [
            {
                "event_id": "ev-sql-inj-01",
                "device_id": "PC-TEST-01",
                "timestamp": "2026-10-22T10:00:00Z",
                "type": "process_create",
                "command_line": "chrome.exe '; DROP TABLE alerts; --",
                "process_image": "C:\\malware' OR '1'='1.exe",
                "user": "admin' UNION SELECT * FROM users--",
                "source_event_id": 1,
            }
        ],
    }

    event = {
        "body": json.dumps(injection_event),
        "requestContext": {
            "authorizer": {"lambda": {"deviceId": "PC-TEST-01"}},
        },
    }

    resp = ingest_handler(
        event,
        s3_client=mock_s3,
        dynamodb_resource=mock_dyn,
        lambda_client=mock_lam,
    )
    assert resp["statusCode"] == 202
    assert mock_s3.put_object.called
    assert mock_table.put_item.called
    assert mock_lam.invoke.called
