"""Security alert notification formatting, throttling, and multi-channel dispatch.

Formats structured alert emails, enforces a 15-minute anti-spam throttle per device+rule combo,
and optionally dispatches to Telegram (PRD Section 10 and Phase 10).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from shared.models import Alert
except ImportError:
    from agent.models import Alert  # type: ignore

logger = logging.getLogger("shared.notifier")

DEFAULT_THROTTLE_SECONDS: int = 900  # 15 minutes


def format_alert_email(alert: Alert, dashboard_url: Optional[str] = None) -> Tuple[str, str]:
    """Generates structured email subject and body for High-severity alerts."""
    subject = f"[HIGH] Browser Hijack Alert — {alert.device_id}"
    base_url = (
        dashboard_url or os.environ.get("DASHBOARD_URL") or "https://dashboard.example.com"
    ).rstrip("/")
    detail_link = f"{base_url}/alerts/{alert.alert_id}"

    rules_str = ", ".join(alert.rule_ids)
    mitre_str = ", ".join(alert.mitre_ids) if alert.mitre_ids else "None"

    raw = alert.raw_event or {}
    ev_type = raw.get("type", "N/A")
    image = raw.get("process_image", "N/A")
    cmd = raw.get("command_line", "N/A")
    parent = raw.get("parent_image", "N/A")
    user = raw.get("user", "N/A")
    reg_key = raw.get("registry_key", "N/A")
    file_path = raw.get("file_path", "N/A")

    body = (
        "======================================================================\n"
        "BROWSER HIJACK DETECTOR — HIGH SEVERITY SECURITY ALERT\n"
        "======================================================================\n"
        f"Device ID:      {alert.device_id}\n"
        f"Alert ID:       {alert.alert_id}\n"
        f"Timestamp:      {alert.timestamp}\n"
        f"Severity:       HIGH (Composite Risk Score: {alert.score})\n"
        f"Rules Fired:    {rules_str}\n"
        f"MITRE ATT&CK:   {mitre_str}\n\n"
        "WHY WAS THIS FLAGGED?\n"
        "----------------------------------------------------------------------\n"
        f"{alert.explanation}\n\n"
        "FORENSIC EVENT DETAILS:\n"
        "----------------------------------------------------------------------\n"
        f"Event Type:     {ev_type}\n"
        f"Process Image:  {image}\n"
        f"Command Line:   {cmd}\n"
        f"Parent Process: {parent}\n"
        f"User Identity:  {user}\n"
        f"Registry Key:   {reg_key}\n"
        f"Target File:    {file_path}\n\n"
        "INVESTIGATION & REMEDIATION DASHBOARD:\n"
        f"{detail_link}\n"
        "======================================================================\n"
    )

    return subject, body


def format_silence_alert(device_id: str, last_seen: str, minutes_silent: int) -> Tuple[str, str]:
    """Generates structured notification for endpoint heartbeat silence."""
    subject = f"[ALERT] Endpoint Silence Detected — {device_id}"
    body = (
        "======================================================================\n"
        "BROWSER HIJACK DETECTOR — ENDPOINT SILENCE WARNING\n"
        "======================================================================\n"
        f"Device ID:       {device_id}\n"
        f"Last Heartbeat:  {last_seen}\n"
        f"Duration Silent: {minutes_silent} minutes (threshold: 10 minutes)\n"
        "Current Status:  Offline\n\n"
        "Impact:\n"
        f"The host '{device_id}' has stopped transmitting health heartbeats.\n"
        "This may indicate the machine was powered off, network connection was lost,\n"
        "or the detection agent process was tampered with by malware.\n\n"
        "Recommended Action:\n"
        "1. Verify the host is powered on and has network connectivity.\n"
        "2. Check if the 'Windows Log-Based Browser Hijack Detector' service is running.\n"
        "======================================================================\n"
    )
    return subject, body


def should_throttle_notification(
    devices_table: Any,
    device_id: str,
    rule_ids: List[str],
    throttle_seconds: int = DEFAULT_THROTTLE_SECONDS,
) -> bool:
    """Checks if a notification for this device+rule combo was sent within the throttle window."""
    rule_key = "#".join(sorted(rule_ids))
    now = time.time()

    try:
        resp = devices_table.get_item(Key={"device_id": device_id})
        item = resp.get("Item") or {}
        last_notifs: Dict[str, Any] = item.get("last_notifications", {})

        last_sent = float(last_notifs.get(rule_key, 0.0))
        if (now - last_sent) < throttle_seconds:
            logger.info(
                f"Notification throttled for {device_id} on {rule_key} "
                f"({int(now - last_sent)}s < {throttle_seconds}s limit)."
            )
            return True
    except Exception as e:
        logger.warning(f"Error checking notification throttle for {device_id}: {e}")

    return False


def record_notification_sent(
    devices_table: Any,
    device_id: str,
    rule_ids: List[str],
) -> None:
    """Updates the last_notifications timestamp for this device+rule combo in DynamoDB."""
    rule_key = "#".join(sorted(rule_ids))
    now = time.time()

    try:
        devices_table.update_item(
            Key={"device_id": device_id},
            UpdateExpression="SET last_notifications.#rk = :now, updated_at = :iso",
            ExpressionAttributeNames={"#rk": rule_key},
            ExpressionAttributeValues={
                ":now": int(now),
                ":iso": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception:
        # If last_notifications attribute does not exist yet on device, initialize it
        try:
            devices_table.update_item(
                Key={"device_id": device_id},
                UpdateExpression="SET last_notifications = :m, updated_at = :iso",
                ExpressionAttributeValues={
                    ":m": {rule_key: int(now)},
                    ":iso": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception as inner_e:
            logger.error(f"Failed to record notification timestamp for {device_id}: {inner_e}")


def send_telegram_alert(bot_token: str, chat_id: str, alert: Alert) -> bool:
    """Sends structured alert message to Telegram chat via Bot API."""
    if not bot_token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    rules_str = ", ".join(alert.rule_ids)
    msg = (
        f"🚨 *[HIGH] Browser Hijack Alert*\n\n"
        f"*Device:* `{alert.device_id}`\n"
        f"*Score:* `{alert.score}` | *Severity:* `HIGH`\n"
        f"*Rules:* {rules_str}\n\n"
        f"*Explanation:*\n{alert.explanation}\n"
    )

    payload = json.dumps(
        {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "Markdown",
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status == 200
    except Exception as e:
        logger.warning(f"Telegram notification delivery failed: {e}")
        return False
