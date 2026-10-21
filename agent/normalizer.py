"""Event normalizer for Windows event logs.

Converts raw event dictionaries from Sysmon, Security, System, and PowerShell
into standardized, privacy-conscious NormalizedEvent schemas matching PRD Section 9.1.
"""

from __future__ import annotations

import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from agent.models import NormalizedEvent

logger = logging.getLogger("agent.normalizer")

# Regex to handle Windows 7-digit timestamp fractional seconds (e.g. .1234567Z -> .123456Z)
SUBSECOND_RE = re.compile(r"\.(\d{1,6})\d*([Zz]|[+-]\d{2}:\d{2})?$")


def normalize_timestamp(ts_str: Optional[str]) -> str:
    """Parses various Windows timestamp formats and returns a uniform ISO 8601 UTC string."""
    if not ts_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ts_clean = ts_str.strip()

    # Convert space separator to 'T' if needed (e.g. '2026-10-21 10:30:15.123')
    if " " in ts_clean and "T" not in ts_clean:
        ts_clean = ts_clean.replace(" ", "T")

    # If it ends with Z or z, strip it for parsing with microseconds
    has_z = ts_clean.endswith("Z") or ts_clean.endswith("z")
    if has_z:
        ts_clean = ts_clean[:-1]

    # Normalize fractional seconds to at most 6 digits
    def _truncate_subseconds(match: re.Match) -> str:
        micro = match.group(1).ljust(6, "0")[:6]
        tz = match.group(2) or ""
        return f".{micro}{tz}"

    ts_clean = SUBSECOND_RE.sub(_truncate_subseconds, ts_clean)

    try:
        dt = datetime.fromisoformat(ts_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception as e:
        logger.debug(f"Failed to parse timestamp '{ts_str}': {e}. Using current UTC time.")
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_string(val: Any, max_len: int = 2048) -> Optional[str]:
    """Cleans a string, strips whitespace, converts empty to None, and enforces max length."""
    if val is None:
        return None
    s = str(val).strip()
    if not s or s.lower() == "none" or s == "-":
        return None
    if len(s) > max_len:
        s = s[:max_len]
    return s


def parse_registry_target(target: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Splits a Windows registry target object into (registry_key, registry_value_name)."""
    clean_target = clean_string(target)
    if not clean_target:
        return None, None

    # Replace common internal registry roots with standard abbreviations
    normalized_path = clean_target
    if normalized_path.startswith("\\REGISTRY\\MACHINE\\"):
        normalized_path = "HKLM\\" + normalized_path[18:]
    elif normalized_path.startswith("\\REGISTRY\\USER\\"):
        normalized_path = "HKCU\\" + normalized_path[15:]

    if "\\" in normalized_path:
        key, val_name = normalized_path.rsplit("\\", 1)
        return clean_string(key), clean_string(val_name)

    return clean_string(normalized_path), None


def extract_task_command(
    task_content: Optional[str], task_name: Optional[str] = None
) -> Optional[str]:
    """Extracts the executable command line from a scheduled task XML definition."""
    if not task_content:
        return clean_string(task_name)

    try:
        root = ET.fromstring(task_content)
        cmd_elem = root.find(".//{*}Command")
        args_elem = root.find(".//{*}Arguments")

        parts: List[str] = []
        if cmd_elem is not None and cmd_elem.text:
            parts.append(cmd_elem.text.strip())
        if args_elem is not None and args_elem.text:
            parts.append(args_elem.text.strip())

        if parts:
            return clean_string(" ".join(parts))
    except Exception:
        pass

    return clean_string(task_name)


def normalize(
    raw_event: Dict[str, Any], device_id: Optional[str] = None
) -> Optional[NormalizedEvent]:
    """Normalizes a single raw event dictionary into a NormalizedEvent object.

    Returns None if the event is unsupported or contains insufficient data.
    """
    if not isinstance(raw_event, dict):
        return None

    channel = raw_event.get("Channel") or ""
    event_id = raw_event.get("EventID", 0)
    record_id = raw_event.get("EventRecordID", 0)
    data = raw_event.get("EventData") or {}
    dev_id = clean_string(device_id) or clean_string(raw_event.get("Computer")) or "UNKNOWN-HOST"
    timestamp = normalize_timestamp(raw_event.get("TimeCreated"))

    event_type: Optional[str] = None
    process_image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    user: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value: Optional[str] = None
    file_path: Optional[str] = None

    # 1. Sysmon Event ID 1: Process Creation
    if "Sysmon" in channel and event_id == 1:
        event_type = "process_create"
        process_image = clean_string(data.get("Image"))
        command_line = clean_string(data.get("CommandLine"))
        parent_image = clean_string(data.get("ParentImage"))
        user = clean_string(data.get("User"))

    # 2. Security Event ID 4688: Process Creation
    elif channel == "Security" and event_id == 4688:
        event_type = "process_create"
        process_image = clean_string(data.get("NewProcessName"))
        command_line = clean_string(data.get("CommandLine"))
        parent_image = clean_string(data.get("ParentProcessName"))
        user = clean_string(data.get("SubjectUserName")) or clean_string(data.get("TargetUserName"))
        domain = clean_string(data.get("SubjectDomainName"))
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"

    # 3. Sysmon Event ID 11: File Creation
    elif "Sysmon" in channel and event_id == 11:
        event_type = "file_create"
        file_path = clean_string(data.get("TargetFilename"))
        process_image = clean_string(data.get("Image"))
        user = clean_string(data.get("User"))

    # 4. Sysmon Event ID 12: Registry Object Added or Deleted
    elif "Sysmon" in channel and event_id == 12:
        event_type = "registry_add"
        target_obj = data.get("TargetObject")
        registry_key, registry_value_name = parse_registry_target(target_obj)
        process_image = clean_string(data.get("Image"))
        user = clean_string(data.get("User"))

    # 5. Sysmon Event ID 13: Registry Value Set
    elif "Sysmon" in channel and event_id == 13:
        event_type = "registry_set"
        target_obj = data.get("TargetObject")
        registry_key, registry_value_name = parse_registry_target(target_obj)
        registry_value = clean_string(data.get("Details"))
        process_image = clean_string(data.get("Image"))
        user = clean_string(data.get("User"))

    # 6. Sysmon Event ID 14: Registry Key / Value Renamed
    elif "Sysmon" in channel and event_id == 14:
        event_type = "registry_rename"
        target_obj = data.get("TargetObject")
        registry_key, registry_value_name = parse_registry_target(target_obj)
        registry_value = clean_string(data.get("NewName"))
        process_image = clean_string(data.get("Image"))
        user = clean_string(data.get("User"))

    # 7. Security Event ID 4698: Scheduled Task Created
    elif channel == "Security" and event_id == 4698:
        event_type = "task_create"
        task_name = clean_string(data.get("TaskName"))
        task_content = data.get("TaskContent")
        command_line = extract_task_command(task_content, task_name)
        registry_value_name = task_name
        user = clean_string(data.get("SubjectUserName"))
        domain = clean_string(data.get("SubjectDomainName"))
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"

    # 8. System Event ID 7045: Service Installed
    elif channel == "System" and event_id == 7045:
        event_type = "service_install"
        svc_name = clean_string(data.get("ServiceName"))
        img_path = clean_string(data.get("ImagePath"))
        process_image = img_path
        command_line = img_path
        registry_value_name = svc_name
        user = clean_string(data.get("AccountName"))

    # 9. Security Event ID 1102: Audit Log Cleared
    elif channel == "Security" and event_id == 1102:
        event_type = "log_cleared"
        user = clean_string(data.get("SubjectUserName"))
        domain = clean_string(data.get("SubjectDomainName"))
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"

    # 10. PowerShell Event ID 4104: Script Block Logging
    elif "PowerShell" in channel and event_id == 4104:
        event_type = "script_execute"
        command_line = clean_string(data.get("ScriptBlockText"))
        user = clean_string(data.get("UserId"))

    # Unsupported or unhandled event
    if event_type is None:
        logger.debug(f"Unhandled or filtered event: Channel={channel}, EventID={event_id}")
        return None

    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        device_id=dev_id,
        timestamp=timestamp,
        type=event_type,
        source_event_id=record_id,
        process_image=process_image,
        command_line=command_line,
        parent_image=parent_image,
        user=user,
        registry_key=registry_key,
        registry_value_name=registry_value_name,
        registry_value=registry_value,
        file_path=file_path,
    )


def normalize_batch(
    events: List[Dict[str, Any]], device_id: Optional[str] = None
) -> List[NormalizedEvent]:
    """Normalizes a batch of raw events, filtering out unhandled types."""
    normalized: List[NormalizedEvent] = []
    for raw in events:
        try:
            norm = normalize(raw, device_id=device_id)
            if norm is not None:
                normalized.append(norm)
        except Exception as e:
            logger.warning(f"Error normalizing event record {raw.get('EventRecordID')}: {e}")
    return normalized
