"""Dashboard API Lambda: Rules, Whitelist & Correlation Catalog Viewer.

Handles:
- GET /rules (detection rules BH001-BH008, correlation rules CR01-CR03, whitelist policies)
(PRD Section 10 and Phase 11).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

import boto3
import yaml

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "hijackdet-dev-config")


def get_s3_client():
    return boto3.client("s3")


def json_response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
        },
        "body": json.dumps(body),
    }


def load_catalog(s3_client: Any) -> Dict[str, Any]:
    """Loads rules, whitelist, and correlations from S3 config bucket."""
    rules_data = {"rules": []}
    correlations_data = {"correlations": []}
    whitelist_data = {"trusted_paths": [], "trusted_publishers": []}

    try:
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/rules.yaml")
        rules_data = yaml.safe_load(resp["Body"].read().decode("utf-8")) or {}
    except Exception as e:
        logger.warning(f"Failed to fetch rules.yaml from S3: {e}")

    try:
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/correlation_rules.yaml")
        correlations_data = yaml.safe_load(resp["Body"].read().decode("utf-8")) or {}
    except Exception as e:
        logger.warning(f"Failed to fetch correlation_rules.yaml from S3: {e}")

    try:
        resp = s3_client.get_object(Bucket=CONFIG_BUCKET, Key="rules/whitelist.yaml")
        whitelist_data = yaml.safe_load(resp["Body"].read().decode("utf-8")) or {}
    except Exception as e:
        logger.warning(f"Failed to fetch whitelist.yaml from S3: {e}")

    return {
        "rules": rules_data.get("rules", []),
        "correlations": correlations_data.get("correlations", []),
        "whitelist": {
            "trusted_paths": whitelist_data.get("trusted_paths", []),
            "trusted_publishers": whitelist_data.get("trusted_publishers", []),
            "suppressed_rules": list(whitelist_data.get("suppressed_rules", {}).keys()),
        },
    }


def handler(event: Dict[str, Any], context: Any = None, s3_client: Any = None) -> Dict[str, Any]:
    """Main HTTP API handler for GET /rules."""
    s3 = s3_client or get_s3_client()
    catalog = load_catalog(s3)
    return json_response(200, catalog)
