"""Dashboard API Lambda: Alerts management and detail viewer.

Handles:
- GET /alerts (filter by device, severity, time range with pagination)
- GET /alerts/{id} (detailed alert context, score breakdown, timeline of related events)
(PRD Section 10 and Phase 11).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key

from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALERTS_TABLE = os.environ.get("ALERTS_TABLE", "hijack-detector-dev-alerts")
EVENT_HISTORY_TABLE = os.environ.get("EVENT_HISTORY_TABLE", "hijack-detector-dev-event-history")


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


def list_alerts(
    table: Any,
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 25,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
) -> Dict[str, Any]:
    """Queries alerts table with optional device, severity, and date range filters."""
    now_iso = datetime.now(timezone.utc).isoformat()
    start_ts = from_time or (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    end_ts = to_time or now_iso

    try:
        if device_id:
            # Query by Hash Key (device_id) + Range Key (timestamp)
            resp = table.query(
                KeyConditionExpression=Key("device_id").eq(device_id)
                & Key("timestamp").between(start_ts, end_ts),
                ScanIndexForward=False,  # Newest first
                Limit=limit,
            )
            items = resp.get("Items", [])
            if severity:
                items = [it for it in items if it.get("severity", "").lower() == severity.lower()]

        elif severity:
            # Query by SeverityIndex GSI
            sev_norm = severity.capitalize()
            resp = table.query(
                IndexName="SeverityIndex",
                KeyConditionExpression=Key("severity").eq(sev_norm)
                & Key("timestamp").between(start_ts, end_ts),
                ScanIndexForward=False,
                Limit=limit,
            )
            items = resp.get("Items", [])

        else:
            # Scan recent alerts
            resp = table.scan(
                FilterExpression=Attr("timestamp").gte(start_ts),
                Limit=limit * 2,
            )
            items = resp.get("Items", [])
            # Sort newest first
            items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            items = items[:limit]

        return {"count": len(items), "alerts": items}
    except Exception as e:
        logger.error(f"Error querying alerts: {e}")
        return {"error": "Failed to query alerts", "details": str(e), "alerts": []}


def get_alert_detail(alerts_table: Any, history_table: Any, alert_id: str) -> Dict[str, Any]:
    """Finds alert by alert_id and loads timeline context from event_history (±10 min)."""
    try:
        # Scan or query for the alert by alert_id
        resp = alerts_table.scan(
            FilterExpression=Attr("alert_id").eq(alert_id),
            Limit=1,
        )
        items = resp.get("Items", [])
        if not items:
            return {"error": "Alert not found", "status_code": 404}

        alert = items[0]
        device_id = alert.get("device_id")
        alert_ts = alert.get("timestamp")

        # Load timeline events ±10 minutes around the alert
        timeline_events: List[Dict[str, Any]] = []
        if device_id and alert_ts:
            try:
                alert_dt = datetime.fromisoformat(alert_ts.replace("Z", "+00:00"))
                window_start = (alert_dt - timedelta(minutes=10)).isoformat()
                window_end = (alert_dt + timedelta(minutes=10)).isoformat()

                hist_resp = history_table.query(
                    KeyConditionExpression=Key("device_id").eq(device_id)
                    & Key("timestamp").between(window_start, window_end),
                    Limit=50,
                )
                timeline_events = hist_resp.get("Items", [])
            except Exception as e:
                logger.warning(f"Error fetching timeline for alert {alert_id}: {e}")

        return {
            "alert": alert,
            "timeline": timeline_events,
            "status_code": 200,
        }
    except Exception as e:
        logger.error(f"Error fetching alert detail: {e}")
        return {"error": str(e), "status_code": 500}


def handler(
    event: Dict[str, Any], context: Any = None, dynamodb_resource: Any = None
) -> Dict[str, Any]:
    """Main HTTP API handler for /alerts and /alerts/{id}."""
    dyn = dynamodb_resource or get_dynamodb_resource()
    alerts_table = dyn.Table(ALERTS_TABLE)
    history_table = dyn.Table(EVENT_HISTORY_TABLE)

    path = event.get("rawPath") or event.get("path") or ""
    path_params = event.get("pathParameters") or {}
    query_params = event.get("queryStringParameters") or {}

    alert_id = path_params.get("id") or path.split("/")[-1] if "/alerts/" in path else None

    # GET /alerts/{id}
    if alert_id and alert_id != "alerts":
        res = get_alert_detail(alerts_table, history_table, alert_id)
        code = res.pop("status_code", 200)
        return json_response(code, res)

    # GET /alerts
    device_filter = query_params.get("device") or query_params.get("device_id")
    severity_filter = query_params.get("severity")
    limit = int(query_params.get("limit", 25))
    from_time = query_params.get("from")
    to_time = query_params.get("to")

    result = list_alerts(
        alerts_table,
        device_id=device_filter,
        severity=severity_filter,
        limit=limit,
        from_time=from_time,
        to_time=to_time,
    )
    return json_response(200, result)
