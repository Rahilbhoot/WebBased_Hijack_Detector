"""Unit tests for the agent heartbeat sender and service."""

from unittest.mock import MagicMock

import requests

from agent.config import AgentConfig
from agent.heartbeat import HeartbeatSender, HeartbeatService


def test_heartbeat_payload_fields(tmp_path):
    queue_file = tmp_path / "queue.sqlite"
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        api_endpoint="https://api.example.com",
        api_key="test-key-123",
        queue_file=queue_file,
    )
    sender = HeartbeatSender(config=cfg)
    sender.record_events_sent(15)

    payload = sender.build_payload()

    assert payload["device_id"] == "PC-TEST-01"
    assert payload["agent_version"] == "1.0.0"
    assert isinstance(payload["uptime_seconds"], int)
    assert payload["uptime_seconds"] >= 0
    assert "timestamp" in payload
    assert "os_version" in payload
    assert "hostname" in payload
    assert payload["total_events_sent"] == 15
    assert payload["event_queue_size"] == 0


def test_heartbeat_send_success():
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        api_endpoint="https://api.example.com",
        api_key="secret-key",
    )
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_session.post.return_value = mock_resp

    sender = HeartbeatSender(config=cfg, session=mock_session)
    success = sender.send_heartbeat()

    assert success is True
    mock_session.post.assert_called_once()
    args, kwargs = mock_session.post.call_args
    assert args[0] == "https://api.example.com/heartbeat"
    assert kwargs["headers"]["x-api-key"] == "secret-key"
    assert kwargs["json"]["device_id"] == "PC-TEST-01"


def test_heartbeat_send_unauthorized():
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        api_endpoint="https://api.example.com",
        api_key="revoked-key",
    )
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    mock_session.post.return_value = mock_resp

    sender = HeartbeatSender(config=cfg, session=mock_session)
    success = sender.send_heartbeat()

    assert success is False


def test_heartbeat_send_network_failure():
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        api_endpoint="https://api.example.com",
        api_key="valid-key",
    )
    mock_session = MagicMock()
    mock_session.post.side_effect = requests.ConnectionError("Network down")

    sender = HeartbeatSender(config=cfg, session=mock_session)
    success = sender.send_heartbeat()

    # Gracefully handle network outage without crashing
    assert success is False


def test_heartbeat_standalone_skip():
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        standalone_mode=True,
    )
    mock_session = MagicMock()
    sender = HeartbeatSender(config=cfg, session=mock_session)
    success = sender.send_heartbeat()

    # In standalone mode, send is skipped
    assert success is True
    mock_session.post.assert_not_called()


def test_heartbeat_service_lifecycle():
    cfg = AgentConfig(
        device_id="PC-TEST-01",
        api_endpoint="https://api.example.com",
        heartbeat_interval_seconds=1,
    )
    mock_sender = MagicMock()
    service = HeartbeatService(config=cfg, sender=mock_sender)

    service.start()
    assert service._thread is not None
    assert service._thread.is_alive()

    # Wait briefly to ensure startup heartbeat was called
    mock_sender.send_heartbeat.assert_called()

    service.stop(timeout=1.0)
    assert not service._thread.is_alive()
