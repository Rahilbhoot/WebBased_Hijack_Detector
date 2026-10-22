"""Unit tests for agent/local_store.py, agent/standalone.py, and agent/sender.py."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.config import AgentConfig
from agent.local_store import LocalStore
from agent.models import Alert, NormalizedEvent
from agent.sender import EventSender
from agent.standalone import StandaloneDetector


def test_store_init_and_tables(tmp_path: Path):
    db_file = tmp_path / "test_store.sqlite"
    store = LocalStore(db_path=db_file)

    cursor = store._conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('events', 'alerts', 'outbox');"
    )
    tables = {r[0] for r in cursor.fetchall()}
    assert tables == {"events", "alerts", "outbox"}

    cursor.execute("PRAGMA journal_mode;")
    mode = cursor.fetchone()[0]
    assert mode.lower() == "wal"
    store.close()


def test_events_insert_and_process(tmp_path: Path):
    db_file = tmp_path / "test_store.sqlite"
    store = LocalStore(db_path=db_file)

    ev1 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="process_create",
        source_event_id=1,
        process_image="C:\\Windows\\notepad.exe",
    )
    ev2 = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:01:00Z",
        type="file_create",
        source_event_id=2,
        file_path="C:\\test.txt",
    )

    store.insert_events([ev1, ev2])

    unprocessed = store.get_unprocessed_events(limit=10)
    assert len(unprocessed) == 2
    assert unprocessed[0].event_id == ev1.event_id
    assert unprocessed[1].event_id == ev2.event_id

    # Mark first processed
    store.mark_events_processed([ev1.event_id])
    remaining = store.get_unprocessed_events(limit=10)
    assert len(remaining) == 1
    assert remaining[0].event_id == ev2.event_id
    store.close()


def test_alerts_insert_and_filter(tmp_path: Path):
    db_file = tmp_path / "test_store.sqlite"
    store = LocalStore(db_path=db_file)

    alert_med = Alert(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        rule_ids=["BH001"],
        score=40,
        severity="Medium",
        explanation="Medium risk alert",
        mitre_ids=["T1090"],
    )
    alert_high = Alert(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:05:00Z",
        rule_ids=["BH007"],
        score=60,
        severity="High",
        explanation="High risk alert",
        mitre_ids=["T1070.001"],
    )

    store.insert_alert(alert_med)
    store.insert_alert(alert_high)

    all_alerts = store.get_alerts()
    assert len(all_alerts) == 2

    high_alerts = store.get_alerts(severity="High")
    assert len(high_alerts) == 1
    assert high_alerts[0].severity == "High"
    assert high_alerts[0].score == 60
    assert high_alerts[0].rule_ids == ["BH007"]
    store.close()


def test_outbox_queue_operations(tmp_path: Path):
    db_file = tmp_path / "test_store.sqlite"
    store = LocalStore(db_path=db_file)

    payload = {"device_id": "PC-LAB-01", "events": [{"event_id": "123"}]}
    row_id = store.enqueue_outbox(payload, event_count=1)
    assert row_id > 0

    stats = store.get_outbox_stats()
    assert stats["total_batches"] == 1
    assert stats["total_events"] == 1

    items = store.peek_outbox(limit=5)
    assert len(items) == 1
    assert items[0]["payload"]["device_id"] == "PC-LAB-01"
    assert items[0]["retry_count"] == 0

    store.increment_outbox_retry(items[0]["id"])
    items_after = store.peek_outbox(limit=5)
    assert items_after[0]["retry_count"] == 1

    store.acknowledge_outbox(items[0]["id"])
    assert store.get_outbox_stats()["total_batches"] == 0
    store.close()


def test_outbox_capacity_pruning(tmp_path: Path):
    db_file = tmp_path / "test_store.sqlite"
    # Small capacity of 30 events
    store = LocalStore(db_path=db_file, max_outbox_events=30)

    store.enqueue_outbox({"batch": 1}, event_count=15)
    store.enqueue_outbox({"batch": 2}, event_count=15)
    assert store.get_outbox_stats()["total_events"] == 30

    # Adding a third batch of 15 exceeds 30 -> oldest batch must be pruned
    store.enqueue_outbox({"batch": 3}, event_count=15)

    stats = store.get_outbox_stats()
    assert stats["total_events"] == 30
    items = store.peek_outbox(limit=5)
    # Batch 1 was dropped, only Batch 2 and 3 remain
    assert [i["payload"]["batch"] for i in items] == [2, 3]
    store.close()


def test_standalone_detector_pipeline(tmp_path: Path):
    db_file = tmp_path / "test_alerts.sqlite"
    store = LocalStore(db_path=db_file)

    cfg = AgentConfig(local_db_file=db_file)
    detector = StandaloneDetector(config=cfg, store=store)

    hijack_event = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:30:15Z",
        type="process_create",
        source_event_id=1001,
        process_image="C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe",
        command_line='chrome.exe --proxy-server="127.0.0.1:9999"',
        parent_image="C:\\Users\\Student\\evil.exe",
        user="LAB\\Student",
    )

    alerts = detector.process_events([hijack_event])

    assert len(alerts) == 1
    assert alerts[0].severity == "Medium"
    assert alerts[0].score == 40
    assert "BH001" in alerts[0].rule_ids

    # Verify persisted in SQLite
    saved_alerts = store.get_alerts()
    assert len(saved_alerts) == 1
    assert saved_alerts[0].alert_id == alerts[0].alert_id
    store.close()


def test_sender_offline_buffering(tmp_path: Path):
    db_file = tmp_path / "queue.sqlite"
    store = LocalStore(db_path=db_file)

    cfg = AgentConfig(
        api_endpoint="https://fake-api.example.com",
        api_key="fake-key",
        queue_file=db_file,
    )
    sender = EventSender(config=cfg, store=store)

    ev = NormalizedEvent(
        device_id="PC-LAB-01",
        timestamp="2026-10-21T10:00:00Z",
        type="process_create",
        source_event_id=1,
    )

    # Mock network connection error
    with patch.object(sender.session, "post", side_effect=Exception("Connection refused")):
        success = sender.send_events([ev])
        assert success is False

    # Event must be safely buffered in SQLite outbox!
    stats = store.get_outbox_stats()
    assert stats["total_batches"] == 1
    assert stats["total_events"] == 1

    # Now simulate reconnection and drain outbox
    mock_resp = MagicMock()
    mock_resp.status_code = 202
    with patch.object(sender.session, "post", return_value=mock_resp):
        drained = sender.drain_outbox()
        assert drained == 1

    # Outbox should now be completely drained
    assert store.get_outbox_stats()["total_batches"] == 0
    store.close()
