"""Unit tests for agent/normalizer.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, cast

from agent.models import NormalizedEvent
from agent.normalizer import (
    clean_string,
    normalize,
    normalize_batch,
    normalize_timestamp,
    parse_registry_target,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_fixture(filename: str) -> Dict[str, Any]:
    with open(FIXTURES_DIR / filename, "r", encoding="utf-8") as f:
        return cast(Dict[str, Any], json.load(f))


def test_normalize_sysmon_1():
    raw = _load_fixture("sample_sysmon_1.json")
    event = normalize(raw, device_id="PC-LAB-01")

    assert event is not None
    assert isinstance(event, NormalizedEvent)
    assert event.type == "process_create"
    assert event.device_id == "PC-LAB-01"
    assert event.source_event_id == 1001
    assert event.process_image == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert event.command_line == '"chrome.exe" --proxy-server=127.0.0.1:9999'
    assert event.parent_image == "C:\\Users\\Student\\AppData\\Local\\Temp\\evil.exe"
    assert event.user == "LAB\\Student"
    assert event.timestamp == "2026-10-21T10:30:15Z"


def test_normalize_sysmon_11():
    raw = _load_fixture("sample_sysmon_11.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "file_create"
    assert event.file_path == "C:\\Windows\\System32\\drivers\\etc\\hosts"
    assert event.process_image == "C:\\Windows\\System32\\notepad.exe"
    assert event.user == "LAB\\Student"
    assert event.device_id == "PC-LAB-01"


def test_normalize_sysmon_13():
    raw = _load_fixture("sample_sysmon_13.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "registry_set"
    assert event.registry_key == "HKLM\\SOFTWARE\\Policies\\Google\\Chrome"
    assert event.registry_value_name == "HomepageLocation"
    assert event.registry_value == "http://malicious-search.example.com"
    assert event.process_image == "C:\\Windows\\regedit.exe"


def test_normalize_security_4688():
    raw = _load_fixture("sample_security_4688.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "process_create"
    expected_image = (
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    )
    assert event.process_image == expected_image
    assert event.command_line == '"msedge.exe" --load-extension=C:\\malicious_ext'
    assert event.parent_image == "C:\\Windows\\explorer.exe"
    assert event.user == "LAB\\Student"


def test_normalize_security_4698():
    raw = _load_fixture("sample_security_4698.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "task_create"
    assert event.registry_value_name == "\\BrowserSearchRedirect"
    assert event.command_line == "powershell.exe -WindowStyle Hidden -Enc aGVsbG8="
    assert event.user == "NT AUTHORITY\\SYSTEM"


def test_normalize_security_1102():
    raw = _load_fixture("sample_security_1102.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "log_cleared"
    assert event.user == "LAB\\AttackerUser"
    assert event.source_event_id == 2003


def test_normalize_system_7045():
    raw = _load_fixture("sample_system_7045.json")
    event = normalize(raw)

    assert event is not None
    assert event.type == "service_install"
    assert event.registry_value_name == "BrowserHelperService"
    assert event.command_line == "C:\\ProgramData\\updater.exe --service"
    assert event.user == "LocalSystem"


def test_timestamp_normalization():
    # Windows 7-digit subsecond timestamp
    ts1 = normalize_timestamp("2026-10-21T10:30:15.1234567Z")
    assert ts1 == "2026-10-21T10:30:15Z"

    # Space-separated timestamp
    ts2 = normalize_timestamp("2026-10-21 14:20:00")
    assert ts2 == "2026-10-21T14:20:00Z"

    # Timezone offset (+05:30) converted to UTC
    ts3 = normalize_timestamp("2026-10-21T15:30:00+05:00")
    assert ts3 == "2026-10-21T10:30:00Z"

    # Empty or None timestamp falls back to valid ISO UTC
    ts4 = normalize_timestamp(None)
    assert ts4.endswith("Z")
    assert len(ts4) == 20


def test_privacy_command_line_truncation():
    raw = _load_fixture("sample_sysmon_1.json")
    # Massive command line > 3000 chars
    raw["EventData"]["CommandLine"] = "A" * 3500
    event = normalize(raw)

    assert event is not None
    assert len(event.command_line or "") == 2048


def test_clean_string_nulls_and_empty():
    assert clean_string(None) is None
    assert clean_string("") is None
    assert clean_string("   ") is None
    assert clean_string("-") is None
    assert clean_string("none") is None
    assert clean_string("  valid_val  ") == "valid_val"


def test_parse_registry_target():
    k, v = parse_registry_target(
        r"\REGISTRY\MACHINE\SOFTWARE\Policies\Google\Chrome\HomepageLocation"
    )
    assert k == r"HKLM\SOFTWARE\Policies\Google\Chrome"
    assert v == "HomepageLocation"

    k2, v2 = parse_registry_target(r"\REGISTRY\USER\Software\Internet Settings\ProxyServer")
    assert k2 == r"HKCU\Software\Internet Settings"
    assert v2 == "ProxyServer"

    k3, v3 = parse_registry_target(None)
    assert k3 is None
    assert v3 is None


def test_unsupported_event_returns_none():
    raw = {
        "Channel": "Application",
        "EventID": 99999,
        "EventRecordID": 1,
        "TimeCreated": "2026-10-21T10:00:00Z",
        "EventData": {},
    }
    assert normalize(raw) is None
    assert normalize("not a dict") is None  # type: ignore


def test_normalize_batch():
    batch = [
        _load_fixture("sample_sysmon_1.json"),
        {"Channel": "Unknown", "EventID": 10},  # Unsupported
        _load_fixture("sample_security_1102.json"),
    ]
    normalized = normalize_batch(batch, device_id="CUSTOM-DEVICE")
    assert len(normalized) == 2
    assert normalized[0].type == "process_create"
    assert normalized[0].device_id == "CUSTOM-DEVICE"
    assert normalized[1].type == "log_cleared"
    assert normalized[1].device_id == "CUSTOM-DEVICE"
