"""Unit tests for agent/rule_engine.py."""

from pathlib import Path

from agent.models import NormalizedEvent
from agent.rule_engine import RuleEngine, calculate_severity

RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "rules.yaml"
WHITELIST_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "whitelist.yaml"


def test_rule_engine_loading():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    assert len(engine.rules) == 8
    rule_ids = [r.id for r in engine.rules]
    assert "BH001" in rule_ids
    assert "BH002" in rule_ids
    assert "BH003" in rule_ids
    assert "BH004" in rule_ids
    assert "BH005" in rule_ids
    assert "BH006" in rule_ids
    assert "BH007" in rule_ids
    assert "BH008" in rule_ids


def test_bh001_proxy_flag_detection():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:30:15Z",
        type="process_create",
        source_event_id=1,
        process_image="C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe",
        command_line='chrome.exe --proxy-server="127.0.0.1:9999"',
        parent_image="C:\\Users\\Student\\AppData\\evil.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH001"
    assert matches[0].base_score == 40
    assert "T1090" in matches[0].mitre_ids
    explanation = matches[0].format_explanation(event)
    assert "--proxy-server" in explanation
    assert "evil.exe" in explanation


def test_bh002_browser_policy_detection():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:31:00Z",
        type="registry_set",
        source_event_id=2,
        registry_key="HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
        registry_value_name="HomepageLocation",
        registry_value="http://evil-search.com",
        process_image="C:\\Users\\Student\\Downloads\\malware.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH002"
    assert matches[0].base_score == 50
    assert "T1112" in matches[0].mitre_ids


def test_bh003_proxy_settings_detection():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:32:00Z",
        type="registry_set",
        source_event_id=3,
        registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        registry_value_name="AutoConfigURL",
        registry_value="http://proxy-pac.attacker.com/proxy.pac",
        process_image="C:\\Users\\Student\\Downloads\\installer.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH003"
    assert matches[0].base_score == 30


def test_bh004_hosts_file_detection():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:33:00Z",
        type="file_create",
        source_event_id=4,
        file_path="C:\\Windows\\System32\\drivers\\etc\\hosts",
        process_image="C:\\Users\\Student\\evil.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH004"
    assert matches[0].base_score == 40


def test_bh005_shortcut_tampering():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:34:00Z",
        type="file_create",
        source_event_id=5,
        file_path="C:\\Users\\Public\\Desktop\\Google Chrome.lnk",
        process_image="C:\\Users\\Student\\Downloads\\setup.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH005"
    assert matches[0].base_score == 30


def test_bh006_scheduled_task():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:35:00Z",
        type="task_create",
        source_event_id=6,
        command_line="cmd.exe /c start chrome.exe --proxy-redirect",
        user="SYSTEM",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH006"
    assert matches[0].base_score == 35


def test_bh007_log_cleared():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:36:00Z",
        type="log_cleared",
        source_event_id=7,
        user="LAB\\Attacker",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH007"
    assert matches[0].base_score == 60


def test_bh008_root_certificate():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)
    event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:37:00Z",
        type="registry_set",
        source_event_id=8,
        registry_key="HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\12345",
        registry_value="CertificateData",
        process_image="C:\\Users\\Student\\AppData\\cert_installer.exe",
        user="LAB\\Student",
    )
    matches = engine.evaluate(event)
    assert len(matches) == 1
    assert matches[0].id == "BH008"
    assert matches[0].base_score == 45


def test_whitelist_suppression():
    engine = RuleEngine(rules_path=RULES_PATH, whitelist_path=WHITELIST_PATH)

    # Edge update binary modifying policy key should be suppressed by rule suppression
    event_edge_update = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:38:00Z",
        type="registry_set",
        source_event_id=9,
        registry_key="HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge",
        registry_value_name="UpdatePolicy",
        process_image="C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        user="NT AUTHORITY\\SYSTEM",
    )
    assert engine.evaluate(event_edge_update) == []

    # Trusted path whitelist (e.g. legitimate Google Chrome binary)
    event_legit = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:39:00Z",
        type="process_create",
        source_event_id=10,
        process_image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        command_line="chrome.exe",  # no suspicious flags
        user="LAB\\Student",
    )
    assert engine.evaluate(event_legit) == []


def test_severity_calculation():
    assert calculate_severity(10) == "Low"
    assert calculate_severity(29) == "Low"
    assert calculate_severity(30) == "Medium"
    assert calculate_severity(59) == "Medium"
    assert calculate_severity(60) == "High"
    assert calculate_severity(100) == "High"
