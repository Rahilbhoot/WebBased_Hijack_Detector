"""Dashboard API Lambda: Devices fleet management and enrollment.

Handles:
- GET /devices (fleet list, online/offline status, agent version)
- POST /devices (enroll new device, generate API key, return plaintext key ONCE)
- DELETE /devices/{id}/key (revoke device API key immediately)
(PRD Section 10 and Phase 11 & 12).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEVICES_TABLE = os.environ.get("DEVICES_TABLE", "hijack-detector-dev-devices")


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def json_response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
        },
        "body": json.dumps(body),
    }


def list_devices(table: Any) -> Dict[str, Any]:
    """Retrieves all registered devices from the fleet registry."""
    try:
        resp = table.scan(
            ProjectionExpression=(
                "device_id, #st, last_seen, agent_version, uptime_seconds, "
                "os_version, event_queue_size, hostname, created_at, updated_at, revoked_at"
            ),
            ExpressionAttributeNames={"#st": "status"},
        )
        devices = resp.get("Items", [])
        devices.sort(key=lambda d: d.get("device_id", ""))
        return {"count": len(devices), "devices": devices}
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        return {"error": "Failed to retrieve devices", "details": str(e), "devices": []}


def register_device(table: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Enrolls a new device and generates an unhashed API key returned ONCE."""
    device_id = payload.get("device_id")
    if not device_id or not isinstance(device_id, str) or not device_id.strip():
        return {"error": "Missing or invalid 'device_id'", "status_code": 400}

    device_id = device_id.strip()

    # Generate secure 32-byte hex API key
    raw_api_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()

    now_iso = datetime.now(timezone.utc).isoformat()
    hostname = payload.get("hostname", device_id)
    notes = payload.get("notes", "")

    item = {
        "device_id": device_id,
        "api_key_hash": key_hash,
        "status": "Online",
        "hostname": hostname,
        "notes": notes,
        "agent_version": "",
        "last_seen": now_iso,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(device_id)",
        )
        logger.info(f"Registered new device '{device_id}'.")
        return {
            "device_id": device_id,
            "api_key": raw_api_key,
            "status": "Online",
            "message": "Store this API key securely. It cannot be retrieved again.",
            "status_code": 201,
        }
    except Exception as e:
        if "ConditionalCheckFailedException" in str(e):
            return {"error": f"Device '{device_id}' is already registered.", "status_code": 409}
        logger.error(f"Failed to register device: {e}")
        return {"error": str(e), "status_code": 500}


def revoke_device_key(table: Any, device_id: str) -> Dict[str, Any]:
    """Immediately revokes a device's access by marking status Revoked."""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        table.update_item(
            Key={"device_id": device_id},
            UpdateExpression="SET #st = :revoked, revoked_at = :now, updated_at = :now",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":revoked": "Revoked",
                ":now": now_iso,
            },
        )
        logger.warning(f"Revoked credentials for device '{device_id}'.")
        return {
            "device_id": device_id,
            "status": "Revoked",
            "revoked_at": now_iso,
            "status_code": 200,
        }
    except Exception as e:
        logger.error(f"Failed to revoke device key: {e}")
        return {"error": str(e), "status_code": 500}


def handler(
    event: Dict[str, Any], context: Any = None, dynamodb_resource: Any = None
) -> Dict[str, Any]:
    """Main HTTP API handler for /devices routes."""
    dyn = dynamodb_resource or get_dynamodb_resource()
    table = dyn.Table(DEVICES_TABLE)

    route_key = event.get("routeKey", "")
    route_method = route_key.split()[0] if " " in route_key else ""
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or route_method
        or "GET"
    )
    path = event.get("rawPath") or event.get("path") or ""
    path_params = event.get("pathParameters") or {}

    # DELETE /devices/{id}/key
    if method == "DELETE":
        device_id = path_params.get("id")
        if not device_id and "/devices/" in path:
            parts = path.split("/")
            if len(parts) >= 3:
                device_id = parts[2]

        if not device_id:
            return json_response(400, {"error": "Missing device_id parameter"})

        res = revoke_device_key(table, device_id)
        code = res.pop("status_code", 200)
        return json_response(code, res)

    # POST /devices (Register)
    if method == "POST":
        raw_body = event.get("body") or "{}"
        try:
            payload = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        except Exception as e:
            return json_response(400, {"error": "Invalid JSON body", "details": str(e)})

        res = register_device(table, payload)
        code = res.pop("status_code", 201)
        return json_response(code, res)

    # GET /devices (List)
    result = list_devices(table)
    return json_response(200, result)
