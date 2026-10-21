"""Unit tests for agent/config.py."""

import os
from pathlib import Path

from agent.config import AgentConfig, ChannelConfig, _expand_env_vars, load_config


def test_channel_config_xpath_building():
    # Channel with no event_ids
    ch1 = ChannelConfig(name="System")
    assert ch1.build_xpath_query() == "*"

    # Channel with single event_id
    ch2 = ChannelConfig(name="System", event_ids=[7045])
    assert ch2.build_xpath_query() == "*[System[(EventID=7045)]]"

    # Channel with multiple event_ids
    ch3 = ChannelConfig(name="Security", event_ids=[4688, 4698, 1102])
    assert ch3.build_xpath_query() == "*[System[(EventID=4688 or EventID=4698 or EventID=1102)]]"


def test_env_var_expansion():
    os.environ["TEST_DEVICE"] = "MY-TEST-PC"
    os.environ["TEST_PORT"] = "8080"

    raw = {
        "device": "${TEST_DEVICE}",
        "port": "${TEST_PORT:-9000}",
        "fallback": "${NON_EXISTENT_VAR:-default_val}",
        "empty_fallback": "${NON_EXISTENT_VAR2}",
        "nested": {
            "items": ["${TEST_DEVICE}", "static"],
        },
    }

    expanded = _expand_env_vars(raw)
    assert expanded["device"] == "MY-TEST-PC"
    assert expanded["port"] == "8080"
    assert expanded["fallback"] == "default_val"
    assert expanded["empty_fallback"] == ""
    assert expanded["nested"]["items"] == ["MY-TEST-PC", "static"]


def test_load_config_defaults(tmp_path: Path):
    dummy_yaml = tmp_path / "dummy_config.yaml"
    dummy_yaml.write_text(
        """
device_id: "CUSTOM-PC"
poll_interval_seconds: 10
channels:
  - name: "System"
    event_ids: [7045]
""",
        encoding="utf-8",
    )

    cfg = load_config(dummy_yaml)
    assert cfg.device_id == "CUSTOM-PC"
    assert cfg.poll_interval_seconds == 10
    assert len(cfg.channels) == 1
    assert cfg.channels[0].name == "System"
    assert cfg.channels[0].event_ids == [7045]
    assert cfg.batch_size == 100  # Default value
    assert cfg.standalone_mode is False


def test_load_config_non_existent():
    cfg = load_config(Path("non_existent_config.yaml"))
    assert isinstance(cfg, AgentConfig)
    assert cfg.poll_interval_seconds == 5
