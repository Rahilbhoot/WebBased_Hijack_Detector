"""Cloud Detection Lambda handler.

Evaluates normalized event batches against detection rules and correlation chains,
calculates composite risk scores, maps MITRE ATT&CK techniques, deduplicates alerts,
persists alerts to DynamoDB, and dispatches High-severity alerts to SNS
(PRD Section 5.2, Section 8.2, and Section 9.2).
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from boto3.dynamodb.conditions import Key

try:
    from shared.correlator import EventCorrelator, parse_iso_utc
    from shared.models import Alert, NormalizedEvent
    from shared.rule_engine import RuleEngine, calculate_severity
except ImportError:
    import importlib

    _corr = importlib.import_module("cloud.lambda.shared.correlator")
    _models = importlib.import_module("cloud.lambda.shared.models")
    _engine = importlib.import_module("cloud.lambda.shared.rule_engine")

    EventCorrelator = _corr.EventCorrelator
    parse_iso_utc = _corr.parse_iso_utc
    Alert = _models.Alert
    NormalizedEvent = _models.NormalizedEvent
    RuleEngine = _engine.RuleEngine
    calculate_severity = _engine.calculate_severity

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "hijackdet-dev-config")
ALERTS_TABLE = os.environ.get("ALERTS_TABLE", "hijack-detector-dev-alerts")
EVENT_HISTORY_TABLE = os.environ.get("EVENT_HISTORY_TABLE", "hijack-detector-dev-event-history")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

RULES_CACHE_TTL_SECONDS = 300  # 5 minutes

# In-memory cache across Lambda invocations
_cached_rule_engine: Optional[RuleEngine] = None
_cached_correlator: Optional[EventCorrelator] = None
_last_cache_time: float = 0.0


def get_s3_client():
    return boto3.client("s3")


def get_dynamodb_resource():
    return boto3.resource("dynamodb")


def get_sns_client():
    return boto3.client("sns")


def load_rules_from_s3(s3_client: Any) -> Tuple[RuleEngine, EventCorrelator]:
    """Loads rules, whitelist, and correlation YAML from S3 configuration bucket."""
    engine = RuleEngine()
    correlator = EventCorrelator()

    try:
        # 1. Load detection rules
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/rules.yaml")
        rules_yaml = resp["Body"].read().decode("utf-8")
        engine.load_rules_data(rules_yaml)

        # 2. Load whitelist
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/whitelist.yaml")
        whitelist_yaml = resp["Body"].read().decode("utf-8")
        engine.load_whitelist_data(whitelist_yaml)

        # 3. Load correlation rules
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/correlation_rules.yaml")
        corr_yaml = resp["Body"].read().decode("utf-8")
        correlator.load_rules_data(corr_yaml)

        logger.info(f"Loaded rules from s3://{CONFIG_BUCKET}/rules/")
    except Exception as e:
        logger.error(f"Error fetching rules from S3: {e}")

    return engine, correlator


def get_cached_detectors(
    s3_client: Any = None, force_refresh: bool = False
) -> Tuple[RuleEngine, EventCorrelator]:
    """Retrieves cached RuleEngine and EventCorrelator instances or refreshes if expired."""
    global _cached_rule_engine, _cached_correlator, _last_cache_time

    now = time.time()
    if (
        force_refresh
        or _cached_rule_engine is None
        or _cached_correlator is None
        or (now - _last_cache_time) > RULES_CACHE_TTL_SECONDS
    ):
        s3 = s3_client or get_s3_client()
        engine, corr = load_rules_from_s3(s3)
        _cached_rule_engine = engine
        _cached_correlator = corr
        _last_cache_time = now

    return _cached_rule_engine, _cached_correlator


def load_recent_event_history(
    history_table: Any, device_id: str, minutes: int = 60
) -> List[Dict[str, Any]]:
    """Queries DynamoDB event_history table for events from the same device in the last N min."""
    since_dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    start_key = since_dt.isoformat()

    try:
        resp = history_table.query(
            KeyConditionExpression=Key("device_id").eq(device_id) & Key("timestamp").gte(start_key),
            Limit=200,
        )
        return resp.get("Items", [])
    except Exception as e:
        logger.warning(f"Error querying event history for correlation on {device_id}: {e}")
        return []


def check_alert_dedup(
    alerts_table: Any, device_id: str, rule_ids: List[str], window_minutes: int = 15
) -> Optional[Dict[str, Any]]:
    """Checks if a matching alert for this device and rule set was generated in the last 15 min."""
    since_dt = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    start_key = since_dt.isoformat()
    target_rule_set = set(rule_ids)

    try:
        resp = alerts_table.query(
            KeyConditionExpression=Key("device_id").eq(device_id) & Key("timestamp").gte(start_key),
            ScanIndexForward=False,  # Newest first
            Limit=20,
        )
        for item in resp.get("Items", []):
            item_rules = set(item.get("rule_ids", []))
            if item_rules == target_rule_set:
                return item
    except Exception as e:
        logger.warning(f"Error checking alert dedup for {device_id}: {e}")

    return None


def publish_high_severity_alert(sns_client: Any, alert: Alert) -> bool:
    """Formats and publishes High-severity alert notification to SNS topic."""
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured, skipping email notification.")
        return False

    subject = f"[HIGH] Browser Hijack Alert — {alert.device_id}"
    rules_str = ", ".join(alert.rule_ids)
    mitre_str = ", ".join(alert.mitre_ids) if alert.mitre_ids else "N/A"

    body = (
        f"Browser Hijack Detector - High Severity Security Alert\n\n"
        f"Device:    {alert.device_id}\n"
        f"Timestamp: {alert.timestamp}\n"
        f"Severity:  {alert.severity} (Score: {alert.score})\n"
        f"Rules:     {rules_str}\n"
        f"MITRE IDs: {mitre_str}\n\n"
        f"Explanation:\n{alert.explanation}\n\n"
        f"Event Type: {alert.raw_event.get('type')}\n"
        f"Process:    {alert.raw_event.get('process_image')}\n"
        f"Command:    {alert.raw_event.get('command_line')}\n"
    )

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject max length 100
            Message=body,
        )
        logger.info(f"Published High-severity alert for {alert.device_id} to SNS.")
        return True
    except Exception as e:
        logger.error(f"Failed to publish alert to SNS: {e}")
        return False


def handler(
    event: Dict[str, Any],
    context: Any = None,
    s3_client: Any = None,
    dynamodb_resource: Any = None,
    sns_client: Any = None,
    override_engine: Optional[RuleEngine] = None,
    override_correlator: Optional[EventCorrelator] = None,
) -> Dict[str, Any]:
    """Main Detection Lambda handler."""
    logger.info("Detect Lambda handler invoked.")

    device_id = event.get("device_id", "unknown")
    batch_id = event.get("batch_id", "")
    raw_events = event.get("events") or []

    if not raw_events:
        logger.info(f"Batch {batch_id} contained no events to evaluate.")
        return {
            "status": "processed",
            "device_id": device_id,
            "batch_id": batch_id,
            "events_evaluated": 0,
            "alerts_generated": 0,
        }

    # 1. Get detector engines (cached or overrides for testability)
    if override_engine and override_correlator:
        engine = override_engine
        correlator = override_correlator
    else:
        engine, correlator = get_cached_detectors(s3_client=s3_client)

    dyn = dynamodb_resource or get_dynamodb_resource()
    alerts_table = dyn.Table(ALERTS_TABLE)
    history_table = dyn.Table(EVENT_HISTORY_TABLE)
    sns = sns_client or get_sns_client()

    # 2. Replay recent history for correlation
    recent_history_items = load_recent_event_history(history_table, device_id, minutes=60)
    for hist_item in recent_history_items:
        hist_ev = NormalizedEvent(
            event_id=hist_item.get("event_id", "hist"),
            device_id=device_id,
            timestamp=hist_item.get("raw_timestamp", hist_item.get("timestamp", "").split("#")[0]),
            type=hist_item.get("type", "unknown"),
            source_event_id=0,
            process_image=hist_item.get("process_image"),
            command_line=hist_item.get("command_line"),
            parent_image=hist_item.get("parent_image"),
            registry_key=hist_item.get("registry_key"),
            file_path=hist_item.get("file_path"),
        )
        # Reconstruct rule_ids if stored
        hist_rules = [hist_item.get("type", "")] if hist_item.get("type") else []
        correlator.record_event(device_id, hist_ev, hist_rules)

    generated_alerts: List[Dict[str, Any]] = []
    high_count: int = 0

    # 3. Evaluate each event
    for raw_ev in raw_events:
        try:
            ev = NormalizedEvent.from_dict(raw_ev)
        except Exception as err:
            logger.warning(f"Could not parse event into NormalizedEvent: {err}")
            continue

        # Evaluate rules and whitelist
        matched_rules = engine.evaluate(ev)
        if not matched_rules:
            continue

        rule_ids = [r.id for r in matched_rules]
        base_score = sum(r.base_score for r in matched_rules)

        # Collect MITRE IDs
        all_mitre_ids: Set[str] = set()
        for r in matched_rules:
            all_mitre_ids.update(r.mitre_ids)

        # Build base explanations
        explanations = [r.format_explanation(ev) for r in matched_rules]

        # Evaluate correlation rules
        correlation_matches = correlator.evaluate(device_id, ev, rule_ids)
        bonus_score = sum(cm.score_bonus for cm in correlation_matches)
        for cm in correlation_matches:
            explanations.append(f"[{cm.rule_id} Correlation] {cm.explanation}")
            rule_ids.append(cm.rule_id)

        # Record event in local correlator history
        correlator.record_event(device_id, ev, rule_ids)

        total_score = base_score + bonus_score
        severity = calculate_severity(total_score)
        full_explanation = "\n\n".join(explanations)

        # 4. Alert deduplication check (15 min window)
        existing_alert = check_alert_dedup(alerts_table, device_id, rule_ids, window_minutes=15)
        if existing_alert:
            logger.info(
                f"Deduplicated alert for {device_id} on rules {rule_ids}. "
                f"Existing alert {existing_alert.get('alert_id')} updated."
            )
            # Update score if higher
            existing_score = int(existing_alert.get("score", 0))
            if total_score > existing_score:
                try:
                    alerts_table.update_item(
                        Key={
                            "device_id": device_id,
                            "timestamp": existing_alert["timestamp"],
                        },
                        UpdateExpression="SET score = :s, severity = :sev, updated_at = :u",
                        ExpressionAttributeValues={
                            ":s": total_score,
                            ":sev": severity,
                            ":u": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                except Exception as e:
                    logger.error(f"Failed to update deduplicated alert: {e}")
            continue

        # 5. Create new alert record
        now_iso = datetime.now(timezone.utc).isoformat()
        alert_obj = Alert(
            alert_id=str(uuid.uuid4()),
            device_id=device_id,
            timestamp=ev.timestamp,
            rule_ids=rule_ids,
            score=total_score,
            severity=severity,
            explanation=full_explanation,
            mitre_ids=sorted(list(all_mitre_ids)),
            raw_event=ev.to_dict(),
        )

        alert_item = alert_obj.to_dict()
        alert_item["created_at"] = now_iso
        alert_item["updated_at"] = now_iso

        try:
            alerts_table.put_item(Item=alert_item)
            logger.info(
                f"Generated alert {alert_obj.alert_id} (Score={total_score}, Severity={severity}) "
                f"for device '{device_id}'"
            )
            generated_alerts.append(alert_item)
        except Exception as e:
            logger.error(f"Error persisting alert {alert_obj.alert_id} to DynamoDB: {e}")

        # 6. Publish High-severity alerts to SNS
        if severity == "High":
            high_count += 1
            publish_high_severity_alert(sns, alert_obj)

    return {
        "status": "processed",
        "device_id": device_id,
        "batch_id": batch_id,
        "events_evaluated": len(raw_events),
        "alerts_generated": len(generated_alerts),
        "high_alerts": high_count,
    }
