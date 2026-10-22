"""Custom Lambda Authorizer for API Gateway HTTP API.

Validates endpoint device API keys by SHA-256 hash lookup in DynamoDB
(PRD Section 8.1 and Section 10).
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Dict, Optional

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEVICES_TABLE_NAME = os.environ.get("DEVICES_TABLE_NAME", "hijack-detector-dev-devices")


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def hash_api_key(raw_key: str) -> str:
    """Calculates SHA-256 hex digest of the raw API key."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def find_device_by_key_hash(
    table: Any, key_hash: str, device_id_hint: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Looks up device record by key hash via direct GetItem or ApiKeyHashIndex query."""
    # 1. If device_id hint is supplied, do direct O(1) GetItem lookup
    if device_id_hint:
        try:
            resp = table.get_item(Key={"device_id": device_id_hint})
            item = resp.get("Item")
            if item and item.get("api_key_hash") == key_hash:
                return item
        except Exception as e:
            logger.warning(f"Direct device lookup failed for {device_id_hint}: {e}")

    # 2. Query ApiKeyHashIndex Global Secondary Index
    try:
        resp = table.query(
            IndexName="ApiKeyHashIndex",
            KeyConditionExpression=Key("api_key_hash").eq(key_hash),
            Limit=1,
        )
        items = resp.get("Items", [])
        if items:
            return items[0]
    except Exception as e:
        logger.warning(f"ApiKeyHashIndex query error: {e}")

    # 3. Fallback scan for small lab environments if GSI is indexing or not populated
    try:
        resp = table.scan(
            FilterExpression=Key("api_key_hash").eq(key_hash),
            Limit=1,
        )
        items = resp.get("Items", [])
        if items:
            return items[0]
    except Exception as e:
        logger.error(f"Fallback scan lookup failed: {e}")

    return None


def generate_simple_response(
    is_authorized: bool, device_id: Optional[str] = None, status: Optional[str] = None
) -> Dict[str, Any]:
    """Generates an HTTP API Gateway 2.0 Simple authorizer response."""
    response: Dict[str, Any] = {"isAuthorized": is_authorized}
    if is_authorized and device_id:
        response["context"] = {
            "deviceId": device_id,
            "status": status or "Online",
        }
    return response


def generate_iam_policy(
    principal_id: str, effect: str, resource: str, context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generates an IAM policy format response for REST or v1 API Gateway authorizers."""
    policy: Dict[str, Any] = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource,
                }
            ],
        },
    }
    if context:
        policy["context"] = context
    return policy


def handler(
    event: Dict[str, Any], context: Any = None, dynamodb_resource: Any = None
) -> Dict[str, Any]:
    """Main Lambda authorizer entrypoint."""
    headers = event.get("headers") or {}
    # Case-insensitive header lookup
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    raw_api_key = normalized_headers.get("x-api-key")
    device_id_hint = normalized_headers.get("x-device-id")

    # Detect if request expects Simple v2 format or IAM Policy format
    is_v2 = event.get("version") == "2.0" or "routeArn" in event
    resource_arn = event.get("methodArn", "*")

    if not raw_api_key or not raw_api_key.strip():
        logger.warning("Authorization rejected: Missing or empty x-api-key header.")
        if is_v2:
            return generate_simple_response(False)
        return generate_iam_policy("anonymous", "Deny", resource_arn)

    key_hash = hash_api_key(raw_api_key)

    dyn = dynamodb_resource or get_dynamodb_resource()
    table = dyn.Table(DEVICES_TABLE_NAME)

    device = find_device_by_key_hash(table, key_hash, device_id_hint=device_id_hint)
    if not device:
        logger.warning("Authorization rejected: Unknown API key hash.")
        if is_v2:
            return generate_simple_response(False)
        return generate_iam_policy("anonymous", "Deny", resource_arn)

    device_id = device.get("device_id", "unknown-device")
    status = device.get("status", "Online")

    if status.lower() == "revoked":
        logger.warning(f"Authorization rejected: Device '{device_id}' status is Revoked.")
        if is_v2:
            return generate_simple_response(False)
        return generate_iam_policy(device_id, "Deny", resource_arn)

    logger.info(f"Authorized device '{device_id}' (status={status}).")
    if is_v2:
        return generate_simple_response(True, device_id=device_id, status=status)
    else:
        return generate_iam_policy(
            principal_id=device_id,
            effect="Allow",
            resource=event.get("methodArn", "*"),
            context={"deviceId": device_id, "status": status},
        )
