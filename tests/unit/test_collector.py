"""Unit tests for agent/collector.py."""

from pathlib import Path

from agent.collector import BookmarkManager, EventCollector, EventParser
from agent.config import AgentConfig, ChannelConfig

# Sample Windows Event XML for Sysmon Event 1 (Process Create)
SAMPLE_SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-21T10:30:15.1234567Z"/>
    <EventRecordID>54321</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>PC-LAB-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-10-21 10:30:15.123</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}</Data>
    <Data Name="ProcessId">4128</Data>
    <Data Name="Image">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
    <Data Name="CommandLine">"chrome.exe" --proxy-server=127.0.0.1:9999</Data>
    <Data Name="CurrentDirectory">C:\\Users\\Student\\Desktop\\</Data>
    <Data Name="User">LAB\\Student</Data>
    <Data Name="ParentProcessId">2104</Data>
    <Data Name="ParentImage">C:\\Users\\Student\\AppData\\Local\\Temp\\malware.exe</Data>
    <Data Name="ParentCommandLine">malware.exe</Data>
  </EventData>
</Event>"""

# Sample Windows Event XML for Security Event 1102 (Log Cleared)
SAMPLE_SECURITY_1102_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ecd8-fede-4de6-a143-b6f5c0e3aac5}"/>
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-21T10:45:00.0000000Z"/>
    <EventRecordID>98765</EventRecordID>
    <Channel>Security</Channel>
    <Computer>PC-LAB-01</Computer>
    <Security UserID="S-1-5-21-12345-67890"/>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-12345-67890</SubjectUserSid>
      <SubjectUserName>AttackerUser</SubjectUserName>
      <SubjectDomainName>LAB</SubjectDomainName>
      <SubjectLogonId>0x12345</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"""


class TestBookmarkManager:
    def test_first_run_missing_file(self, tmp_path: Path):
        bm_file = tmp_path / "data" / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        assert bm.get_last_record_id("System") is None
        assert bm.bookmarks == {}

    def test_save_and_reload(self, tmp_path: Path):
        bm_file = tmp_path / "data" / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        bm.update("System", 100)
        bm.update("Security", 250)
        bm.save()

        assert bm_file.is_file()

        # Reload with fresh instance
        bm2 = BookmarkManager(bm_file)
        assert bm2.get_last_record_id("System") == 100
        assert bm2.get_last_record_id("Security") == 250

    def test_corrupted_file_recovery(self, tmp_path: Path):
        bm_file = tmp_path / "data" / "bookmarks.json"
        bm_file.parent.mkdir(parents=True, exist_ok=True)
        bm_file.write_text("{CORRUPTED_JSON_CONTENT:::;", encoding="utf-8")

        bm = BookmarkManager(bm_file)
        assert bm.bookmarks == {}

        # Verify corrupted backup exists
        backup = bm_file.with_suffix(".corrupt.bak")
        assert backup.is_file()

    def test_monotonic_update(self, tmp_path: Path):
        bm_file = tmp_path / "data" / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        bm.update("System", 500)
        # Attempting to update with an older record ID must not regress
        bm.update("System", 400)
        assert bm.get_last_record_id("System") == 500


class TestEventParser:
    def test_parse_sysmon_event(self):
        parsed = EventParser.parse_xml(SAMPLE_SYSMON_XML)
        assert parsed is not None
        assert parsed["Channel"] == "Microsoft-Windows-Sysmon/Operational"
        assert parsed["EventID"] == 1
        assert parsed["EventRecordID"] == 54321
        assert parsed["TimeCreated"] == "2026-10-21T10:30:15.1234567Z"
        assert parsed["Computer"] == "PC-LAB-01"

        data = parsed["EventData"]
        assert data["Image"] == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        assert "--proxy-server=127.0.0.1:9999" in data["CommandLine"]
        assert data["ParentImage"] == "C:\\Users\\Student\\AppData\\Local\\Temp\\malware.exe"
        assert data["User"] == "LAB\\Student"

    def test_parse_security_userdata(self):
        parsed = EventParser.parse_xml(SAMPLE_SECURITY_1102_XML)
        assert parsed is not None
        assert parsed["Channel"] == "Security"
        assert parsed["EventID"] == 1102
        assert parsed["EventRecordID"] == 98765

    def test_parse_invalid_xml(self):
        assert EventParser.parse_xml("NOT_XML") is None
        assert EventParser.parse_xml("") is None


class TestEventCollectorQueryBuilding:
    def test_xpath_without_bookmark(self, tmp_path: Path):
        bm_file = tmp_path / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        cfg = AgentConfig(bookmark_file=bm_file)
        collector = EventCollector(config=cfg, bookmark_manager=bm)

        ch = ChannelConfig(name="System", event_ids=[7045])
        xpath = collector.build_query_for_channel(ch)
        assert xpath == "*[System[(EventID=7045)]]"

    def test_xpath_with_bookmark(self, tmp_path: Path):
        bm_file = tmp_path / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        bm.update("System", 1234)
        cfg = AgentConfig(bookmark_file=bm_file)
        collector = EventCollector(config=cfg, bookmark_manager=bm)

        ch = ChannelConfig(name="System", event_ids=[7045])
        xpath = collector.build_query_for_channel(ch)
        assert xpath == "*[System[EventRecordID > 1234 and (EventID=7045)]]"

    def test_xpath_multiple_events_with_bookmark(self, tmp_path: Path):
        bm_file = tmp_path / "bookmarks.json"
        bm = BookmarkManager(bm_file)
        bm.update("Security", 5000)
        cfg = AgentConfig(bookmark_file=bm_file)
        collector = EventCollector(config=cfg, bookmark_manager=bm)

        ch = ChannelConfig(name="Security", event_ids=[4688, 4698, 1102])
        xpath = collector.build_query_for_channel(ch)
        expected = (
            "*[System[EventRecordID > 5000 and (EventID=4688 or EventID=4698 or EventID=1102)]]"
        )
        assert xpath == expected
