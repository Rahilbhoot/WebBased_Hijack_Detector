"""Unit tests for agent/correlator.py."""

from pathlib import Path

from agent.correlator import EventCorrelator
from agent.models import NormalizedEvent

CORRELATIONS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "rules" / "correlation_rules.yaml"
)


def test_cr01_policy_then_browser():
    correlator = EventCorrelator(correlations_path=CORRELATIONS_PATH)
    assert len(correlator.rules) == 3

    # Event 1: Policy registry modified (BH002) at 10:00:00
    ev1 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="registry_set",
        source_event_id=1,
        registry_key="HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
    )
    correlator.record_event("PC-LAB-01", ev1, ["BH002"])

    # Event 2: Browser launched with proxy flag (BH001) at 10:03:00 (within 5 min window)
    ev2 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:03:00Z",
        type="process_create",
        source_event_id=2,
        command_line="chrome.exe --proxy-server=127.0.0.1:9999",
    )
    matches = correlator.evaluate("PC-LAB-01", ev2, ["BH001"])

    assert len(matches) == 1
    assert matches[0].rule_id == "CR01"
    assert matches[0].score_bonus == 30
    assert "Correlated attack sequence" in matches[0].explanation


def test_cr01_exceeding_window():
    correlator = EventCorrelator(correlations_path=CORRELATIONS_PATH)

    # Event 1 at 10:00:00
    ev1 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="registry_set",
        source_event_id=1,
    )
    correlator.record_event("PC-LAB-01", ev1, ["BH002"])

    # Event 2 at 10:10:00 (10 minutes later > 300s window)
    ev2 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:10:00Z",
        type="process_create",
        source_event_id=2,
    )
    matches = correlator.evaluate("PC-LAB-01", ev2, ["BH001"])
    assert len(matches) == 0


def test_cr02_proxy_and_hosts():
    correlator = EventCorrelator(correlations_path=CORRELATIONS_PATH)

    # Event 1: Proxy change (BH003) at 10:00:00
    ev1 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="registry_set",
        source_event_id=1,
    )
    correlator.record_event("PC-LAB-01", ev1, ["BH003"])

    # Event 2: Hosts file change (BH004) at 10:07:00 (within 10 min window)
    ev2 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:07:00Z",
        type="file_create",
        source_event_id=2,
    )
    matches = correlator.evaluate("PC-LAB-01", ev2, ["BH004"])

    assert len(matches) == 1
    assert matches[0].rule_id == "CR02"
    assert matches[0].score_bonus == 25


def test_cr03_detection_followed_by_log_clearing():
    correlator = EventCorrelator(correlations_path=CORRELATIONS_PATH)

    # Event 1: Browser launched with proxy flag (BH001) at 10:00:00
    ev1 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="process_create",
        source_event_id=1,
    )
    correlator.record_event("PC-LAB-01", ev1, ["BH001"])

    # Event 2: Security log cleared (BH007) at 10:25:00 (within 60 min window)
    ev2 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:25:00Z",
        type="log_cleared",
        source_event_id=2,
    )
    matches = correlator.evaluate("PC-LAB-01", ev2, ["BH007"])

    assert len(matches) == 1
    assert matches[0].rule_id == "CR03"
    assert matches[0].score_bonus == 30


def test_device_isolation():
    correlator = EventCorrelator(correlations_path=CORRELATIONS_PATH)

    ev_pc1 = NormalizedEvent(
        device_id="PC-01",
        timestamp="2026-10-21T10:00:00Z",
        type="registry_set",
        source_event_id=1,
    )
    correlator.record_event("PC-01", ev_pc1, ["BH002"])

    # Event on PC-02 should NOT correlate with PC-01
    ev_pc2 = NormalizedEvent(
        device_id="PC-02",
        timestamp="2026-10-21T10:02:00Z",
        type="process_create",
        source_event_id=2,
    )
    matches = correlator.evaluate("PC-02", ev_pc2, ["BH001"])
    assert len(matches) == 0
