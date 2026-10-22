"""Cloud Ingestion Lambda handler (POST /events).

Receives event batches from endpoint agents, validates payloads, enforces deduplication,
archives raw event batches to S3 (WORM compliance), and invokes the Detect Lambda
(PRD Section 8.2, Section 8.4, and Section 9.2).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

try:
    from shared.validators import (
        validate_batch_payload,
        validate_payload_size,
    )
except ImportError:
    import importlib

    _val_mod = importlib.import_module("cloud.lambda.shared.validators")
    validate_batch_payload = _val_mod.validate_batch_payload
    validate_payload_size = _val_mod.validate_payload_size

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RAW_LOGS_BUCKET = os.environ.get("RAW_LOGS_BUCKET", "hijackdet-dev-rawlogs")
EVENT_HISTORY_TABLE = os.environ.get("EVENT_HISTORY_TABLE", "hijack-detector-dev-event-history")
DETECT_LAMBDA_NAME = os.environ.get("DETECT_LAMBDA_NAME", "hijack-detector-dev-detect")
EVENT_TTL_HOURS = int(os.environ.get("EVENT_TTL_HOURS", "1"))


def get_s3_client():
    return boto3.client("s3")


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def get_lambda_client():
    return boto3.client("lambda")


def generate_s3_key(device_id: str, now: Optional[datetime] = None) -> str:
    """Generates S3 key formatted as: {device_id}/YYYY/MM/DD/HH-mm-ss-{uuid}.json"""
    dt = now or datetime.now(timezone.utc)
    batch_uuid = uuid.uuid4().hex[:12]
    date_path = dt.strftime("%Y/%m/%d")
    timestamp_part = dt.strftime("%H-%M-%S")
    return f"{device_id}/{date_path}/{timestamp_part}-{batch_uuid}.json"


def record_event_history(
    table: Any, device_id: str, event: Dict[str, Any], ttl_seconds: int = 3600
) -> bool:
    """Records event in event_history table with TTL for deduplication and sliding window.

    Returns:
        True if event is new, False if it was a duplicate.
    """
    event_id = event["event_id"]
    timestamp = event["timestamp"]
    ttl_timestamp = int(time.time()) + ttl_seconds
    sort_key = f"{timestamp}#{event_id}"

    item = {
        "device_id": device_id,
        "timestamp": sort_key,
        "event_id": event_id,
        "raw_timestamp": timestamp,
        "type": event.get("type"),
        "process_image": event.get("process_image") or "",
        "command_line": event.get("command_line") or "",
        "parent_image": event.get("parent_image") or "",
        "registry_key": event.get("registry_key") or "",
        "file_path": event.get("file_path") or "",
        "ttl": ttl_timestamp,
    }

    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(device_id) AND attribute_not_exists(#ts)",
            ExpressionAttributeNames={"#ts": "timestamp"},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info(f"Duplicate event skipped: {event_id} on {device_id}")
            return False
        logger.error(f"Error persisting event {event_id} to history: {e}")
        # Allow event through on DynamoDB transient errors so we don't drop logs
        return True


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


def handler(
    event: Dict[str, Any],
    context: Any = None,
    s3_client: Any = None,
    dynamodb_resource: Any = None,
    lambda_client: Any = None,
) -> Dict[str, Any]:
    """Ingestion Lambda handler for POST /events."""
    # 1. Parse raw body
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded", False):
        try:
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        except Exception as e:
            return json_response(400, {"error": "Invalid base64 payload", "details": str(e)})

    # 2. Validate payload size (<= 256 KB)
    size_ok, size_err = validate_payload_size(raw_body)
    if not size_ok:
        logger.warning(f"Payload rejected: {size_err}")
        return json_response(413, {"error": "Payload Too Large", "message": size_err})

    # 3. Parse JSON
    try:
        payload = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
    except json.JSONDecodeError as e:
        return json_response(400, {"error": "Invalid JSON format", "details": str(e)})

    # 4. Extract authorizer context device_id (if authenticated via API Gateway authorizer)
    req_context = event.get("requestContext") or {}
    auth_context = req_context.get("authorizer", {}).get("lambda", {}) or req_context.get(
        "authorizer", {}
    )
    auth_device_id = auth_context.get("deviceId") or auth_context.get("device_id")

    # 5. Validate batch schema
    valid_batch, batch_err, events = validate_batch_payload(payload)
    if not valid_batch:
        logger.warning(f"Batch validation failed: {batch_err}")
        return json_response(400, {"error": "Bad Request", "message": batch_err})

    payload_device_id = payload["device_id"]
    if auth_device_id and auth_device_id != payload_device_id:
        logger.error(
            f"Device ID spoofing detected: authorizer identity '{auth_device_id}' "
            f"!= payload device_id '{payload_device_id}'"
        )
        return json_response(
            403,
            {
                "error": "Forbidden",
                "message": "Device ID does not match authenticated credential identity.",
            },
        )

    device_id = payload_device_id

    # 6. Archive raw batch to S3 (WORM compliance)
    s3 = s3_client or get_s3_client()
    s3_key = generate_s3_key(device_id)
    try:
        s3.put_object(
            Bucket=RAW_LOGS_BUCKET,
            Key=s3_key,
            Body=json.dumps(payload, indent=2).encode("utf-8"),
            ContentType="application/json",
            Metadata={
                "device_id": device_id,
                "event_count": str(len(events)),
            },
        )
        logger.info(f"Raw batch archived to s3://{RAW_LOGS_BUCKET}/{s3_key}")
    except Exception as e:
        logger.error(f"Failed to archive raw batch to S3: {e}")
        # Return 500 so client knows to retry offline queue
        return json_response(
            500, {"error": "Storage Failure", "message": "Failed to archive raw batch to S3."}
        )

    # 7. Deduplicate events and record in event_history
    dyn = dynamodb_resource or get_dynamodb_resource()
    history_table = dyn.Table(EVENT_HISTORY_TABLE)

    accepted_events: List[Dict[str, Any]] = []
    duplicate_count: int = 0

    for ev in events:
        is_new = record_event_history(
            history_table, device_id, ev, ttl_seconds=EVENT_TTL_HOURS * 3600
        )
        if is_new:
            accepted_events.append(ev)
        else:
            duplicate_count += 1

    # 8. Asynchronously invoke Detect Lambda for newly accepted events
    batch_id = uuid.uuid4().hex
    if accepted_events and DETECT_LAMBDA_NAME:
        invoker = lambda_client or get_lambda_client()
        detect_payload = {
            "batch_id": batch_id,
            "device_id": device_id,
            "s3_key": s3_key,
            "events": accepted_events,
        }
        try:
            invoker.invoke(
                FunctionName=DETECT_LAMBDA_NAME,
                InvocationType="Event",  # Asynchronous execution
                Payload=json.dumps(detect_payload).encode("utf-8"),
            )
            logger.info(
                f"Dispatched {len(accepted_events)} event(s) to Detect Lambda: "
                f"'{DETECT_LAMBDA_NAME}'"
            )
        except Exception as e:
            logger.error(f"Failed to trigger Detect Lambda: {e}")

    # 9. Return 202 Accepted
    return json_response(
        202,
        {
            "status": "accepted",
            "batch_id": batch_id,
            "device_id": device_id,
            "accepted_count": len(accepted_events),
            "duplicate_count": duplicate_count,
            "s3_key": s3_key,
        },
    )
