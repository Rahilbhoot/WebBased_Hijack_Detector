"""Unit tests for the unified agent service runner."""

from unittest.mock import MagicMock, patch

from agent.config import AgentConfig
from agent.service import HijackDetectorService


@patch("agent.service.load_config")
@patch("agent.service.setup_logger")
def test_agent_service_initialization(mock_logger, mock_load_config, tmp_path):
    mock_load_config.return_value = AgentConfig(
        device_id="PC-SERVICE-TEST",
        standalone_mode=True,
        queue_file=tmp_path / "queue.sqlite",
        local_db_file=tmp_path / "local.sqlite",
        log_file=tmp_path / "agent.log",
        rules_file=tmp_path / "rules.yaml",
        whitelist_file=tmp_path / "whitelist.yaml",
    )

    with patch("agent.service.RuleEngine.from_yaml") as mock_rules, \
         patch("agent.service.EventCorrelator") as mock_corr:
        mock_rules.return_value = MagicMock()
        mock_corr.return_value = MagicMock()

        svc = HijackDetectorService()
        assert svc.config.device_id == "PC-SERVICE-TEST"
        assert svc.config.standalone_mode is True


@patch("agent.service.load_config")
@patch("agent.service.setup_logger")
def test_agent_service_lifecycle(mock_logger, mock_load_config, tmp_path):
    mock_load_config.return_value = AgentConfig(
        device_id="PC-SERVICE-TEST",
        standalone_mode=False,
        api_endpoint="https://api.example.com",
        queue_file=tmp_path / "queue.sqlite",
        local_db_file=tmp_path / "local.sqlite",
        log_file=tmp_path / "agent.log",
        rules_file=tmp_path / "rules.yaml",
        whitelist_file=tmp_path / "whitelist.yaml",
        poll_interval_seconds=1,
    )

    with patch("agent.service.RuleEngine.from_yaml") as mock_rules, \
         patch("agent.service.EventCorrelator") as mock_corr:
        mock_rules.return_value = MagicMock()
        mock_corr.return_value = MagicMock()

        svc = HijackDetectorService()
        svc.collector = MagicMock()
        svc.collector.collect_all.return_value = []
        svc.heartbeat_service = MagicMock()

        # Non-blocking start
        svc.start(blocking=False)
        assert svc._main_thread is not None
        assert svc._main_thread.is_alive()
        svc.heartbeat_service.start.assert_called_once()

        # Stop service
        svc.stop()
        svc._main_thread.join(timeout=1.0)
        assert not svc._main_thread.is_alive()
        svc.heartbeat_service.stop.assert_called_once()
