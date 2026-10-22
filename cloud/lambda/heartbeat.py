"""Endpoint Heartbeat & Silence Alerting Lambda handler.

Serves two primary functions (PRD Section 10 and Phase 10 & 12):
1. Inbound POST /heartbeat from endpoint agents (updates device last_seen and status to Online).
2. Scheduled EventBridge check (every 5 min): detects devices silent for > 10 min, marks them
   Offline, and publishes a silence alert to Amazon SNS.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3

try:
    from shared.notifier import format_silence_alert
except ImportError:
    import importlib

    _notif = importlib.import_module("cloud.lambda.shared.notifier")
    format_silence_alert = _notif.format_silence_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEVICES_TABLE_NAME = os.environ.get("DEVICES_TABLE_NAME", "hijack-detector-dev-devices")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SILENCE_THRESHOLD_SECONDS = int(os.environ.get("SILENCE_THRESHOLD_SECONDS", "600"))  # 10 minutes


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def get_sns_client():
    return boto3.client("sns")


def json_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Formats standard HTTP response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def handle_heartbeat_post(event: Dict[str, Any], table: Any) -> Dict[str, Any]:
    """Handles inbound agent heartbeat POST /heartbeat."""
    raw_body = event.get("body") or "{}"
    try:
        payload = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
    except Exception as e:
        return json_response(400, {"error": "Invalid JSON body", "details": str(e)})

    device_id = payload.get("device_id")
    if not device_id or not isinstance(device_id, str):
        return json_response(400, {"error": "Missing required field: 'device_id'"})

    # Verify against authorizer context if authenticated
    req_context = event.get("requestContext") or {}
    auth_context = req_context.get("authorizer", {}).get("lambda", {}) or req_context.get(
        "authorizer", {}
    )
    auth_device_id = auth_context.get("deviceId") or auth_context.get("device_id")
    if auth_device_id and auth_device_id != device_id:
        return json_response(403, {"error": "Forbidden: Device ID mismatch."})

    now_epoch = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()

    agent_version = str(payload.get("agent_version", "1.0.0"))
    uptime_seconds = int(payload.get("uptime_seconds", 0))
    os_version = str(payload.get("os_version", "Windows"))
    queue_size = int(payload.get("event_queue_size", 0))
    hostname = str(payload.get("hostname", ""))
    total_events_sent = int(payload.get("total_events_sent", 0))

    # Source IP from HTTP request context or payload
    source_ip = str(
        req_context.get("http", {}).get("sourceIp")
        or payload.get("ip_address")
        or ""
    )

    update_parts = [
        "#st = :online",
        "last_seen = :iso",
        "last_seen_epoch = :epoch",
        "agent_version = :ver",
        "uptime_seconds = :uptime",
        "os_version = :os",
        "event_queue_size = :qs",
        "updated_at = :iso",
    ]
    expr_vals = {
        ":online": "Online",
        ":iso": now_iso,
        ":epoch": now_epoch,
        ":ver": agent_version,
        ":uptime": uptime_seconds,
        ":os": os_version,
        ":qs": queue_size,
    }

    if hostname:
        update_parts.append("hostname = :host")
        expr_vals[":host"] = hostname
    if source_ip:
        update_parts.append("ip_address = :ip")
        expr_vals[":ip"] = source_ip
    if total_events_sent > 0:
        update_parts.append("total_events_sent = :tot")
        expr_vals[":tot"] = total_events_sent

    try:
        table.update_item(
            Key={"device_id": device_id},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues=expr_vals,
        )
        logger.info(f"Recorded heartbeat for device '{device_id}' (uptime={uptime_seconds}s).")
        return json_response(
            200,
            {
                "status": "recorded",
                "device_id": device_id,
                "timestamp": now_iso,
            },
        )
    except Exception as e:
        logger.error(f"Failed to record heartbeat in DynamoDB: {e}")
        return json_response(500, {"error": "Storage Failure", "message": str(e)})


def check_silent_devices(table: Any, sns_client: Any) -> Dict[str, Any]:
    """Scans devices table and alerts for hosts that have stopped sending heartbeats."""
    now_epoch = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()
    silent_devices: List[str] = []

    try:
        # Scan for active devices
        resp = table.scan(
            ProjectionExpression="device_id, #st, last_seen, last_seen_epoch",
            ExpressionAttributeNames={"#st": "status"},
        )
        items = resp.get("Items", [])
    except Exception as e:
        logger.error(f"Failed to scan devices table for silence check: {e}")
        return {"status": "error", "error": str(e)}

    for item in items:
        status = item.get("status", "Online")
        if status.lower() != "online":
            continue

        device_id = item["device_id"]
        last_epoch = item.get("last_seen_epoch")
        last_seen = item.get("last_seen", "Unknown")

        if last_epoch is None:
            # Fallback parse ISO if epoch not present
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                last_epoch = int(dt.timestamp())
            except Exception:
                continue

        silence_duration = now_epoch - int(last_epoch)
        if silence_duration > SILENCE_THRESHOLD_SECONDS:
            minutes_silent = silence_duration // 60
            logger.warning(
                f"Device '{device_id}' has gone silent for {minutes_silent} min "
                f"(threshold={SILENCE_THRESHOLD_SECONDS // 60} min)."
            )

            # 1. Update status to Offline
            try:
                table.update_item(
                    Key={"device_id": device_id},
                    UpdateExpression="SET #st = :offline, updated_at = :iso",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":offline": "Offline",
                        ":iso": now_iso,
                    },
                )
                silent_devices.append(device_id)
            except Exception as e:
                logger.error(f"Failed to set device {device_id} offline: {e}")

            # 2. Publish Silence Alert to SNS
            if SNS_TOPIC_ARN:
                subject, body = format_silence_alert(device_id, last_seen, minutes_silent)
                try:
                    sns_client.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Subject=subject[:100],
                        Message=body,
                    )
                    logger.info(f"Published silence alert for {device_id} to SNS.")
                except Exception as e:
                    logger.error(f"Failed to publish silence alert to SNS: {e}")

    return {
        "status": "checked",
        "scanned_count": len(items),
        "silent_count": len(silent_devices),
        "silent_devices": silent_devices,
    }


def handler(
    event: Dict[str, Any],
    context: Any = None,
    dynamodb_resource: Any = None,
    sns_client: Any = None,
) -> Dict[str, Any]:
    """Unified handler supporting both HTTP POST /heartbeat and EventBridge scheduled checks."""
    dyn = dynamodb_resource or get_dynamodb_resource()
    table = dyn.Table(DEVICES_TABLE_NAME)
    sns = sns_client or get_sns_client()

    # Detect if invoked by EventBridge scheduled event
    is_scheduled = (
        event.get("source") == "aws.events"
        or event.get("detail-type") == "Scheduled Event"
        or "time" in event
        and "resources" in event
    )

    if is_scheduled or event.get("action") == "check_silence":
        logger.info("Executing scheduled endpoint silence check...")
        return check_silent_devices(table, sns)

    # Otherwise handle HTTP POST /heartbeat
    return handle_heartbeat_post(event, table)
