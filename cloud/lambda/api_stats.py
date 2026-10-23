"""Dashboard API Lambda: Aggregate fleet and security statistics.

Handles:
- GET /stats (24h alert counts, severity breakdown, online/offline device counts, top rules)
(PRD Section 10 and Phase 11).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALERTS_TABLE = os.environ.get("ALERTS_TABLE", "hijack-detector-dev-alerts")
DEVICES_TABLE = os.environ.get("DEVICES_TABLE", "hijack-detector-dev-devices")


def decimal_default(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, (datetime, )):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def json_response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
        },
        "body": json.dumps(body, default=decimal_default),
    }


def aggregate_stats(alerts_table: Any, devices_table: Any) -> Dict[str, Any]:
    """Computes fleet overview and 24-hour security incident aggregates."""
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = (now - timedelta(hours=24)).isoformat()

    # 1. Fetch 24h alerts
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    rule_counts: Dict[str, int] = {}
    recent_alerts: List[Dict[str, Any]] = []

    try:
        resp = alerts_table.scan(
            FilterExpression=Attr("timestamp").gte(twenty_four_hours_ago),
            Limit=500,
        )
        alerts_24h = resp.get("Items", [])
        for a in alerts_24h:
            sev = a.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1

            for r_id in a.get("rule_ids", []):
                rule_counts[r_id] = rule_counts.get(r_id, 0) + 1

        # Sort recent alerts
        alerts_24h.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        recent_alerts = alerts_24h[:10]
    except Exception as e:
        logger.error(f"Error fetching alert stats: {e}")

    # 2. Fetch fleet device status
    device_counts = {"total": 0, "online": 0, "offline": 0, "revoked": 0}
    try:
        dev_resp = devices_table.scan(
            ProjectionExpression="#st",
            ExpressionAttributeNames={"#st": "status"},
        )
        devices = dev_resp.get("Items", [])
        device_counts["total"] = len(devices)
        for d in devices:
            st = d.get("status", "Online").lower()
            if st == "online":
                device_counts["online"] += 1
            elif st == "offline":
                device_counts["offline"] += 1
            elif st == "revoked":
                device_counts["revoked"] += 1
    except Exception as e:
        logger.error(f"Error fetching device stats: {e}")

    # Top triggered rules
    top_rules = sorted(
        [{"rule_id": k, "count": v} for k, v in rule_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    return {
        "timestamp": now.isoformat(),
        "total_alerts_24h": sum(severity_counts.values()),
        "severity_distribution": severity_counts,
        "fleet_status": device_counts,
        "top_rules": top_rules,
        "recent_alerts": recent_alerts,
    }


def handler(
    event: Dict[str, Any], context: Any = None, dynamodb_resource: Any = None
) -> Dict[str, Any]:
    """Main HTTP API handler for GET /stats."""
    dyn = dynamodb_resource or get_dynamodb_resource()
    alerts_table = dyn.Table(ALERTS_TABLE)
    devices_table = dyn.Table(DEVICES_TABLE)

    stats = aggregate_stats(alerts_table, devices_table)
    return json_response(200, stats)
