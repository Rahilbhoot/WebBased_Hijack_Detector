"""Enroll an endpoint device and generate a one-time API key.

Can be run directly via:
python scripts/enroll_device.py --device-id PC-LAB-01
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
import boto3
# Simple .env parser without external dependencies
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

DEVICES_TABLE = os.environ.get("DYNAMODB_DEVICES_TABLE", "hijack-detector-dev-devices")
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")


def enroll(device_id: str, hostname: str | None = None) -> dict:
    hostname = hostname or device_id
    raw_api_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    item = {
        "device_id": device_id,
        "api_key_hash": key_hash,
        "status": "Online",
        "hostname": hostname,
        "agent_version": "1.0.0",
        "last_seen": now_iso,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table(DEVICES_TABLE)

    # Put or overwrite device registration
    table.put_item(Item=item)

    return {
        "device_id": device_id,
        "api_key": raw_api_key,
        "status": "Online",
        "table": DEVICES_TABLE,
    }


def main():
    parser = argparse.ArgumentParser(description="Enroll a device and generate an API key.")
    parser.add_argument("--device-id", default=os.environ.get("DEVICE_ID", "PC-LAB-01"), help="Device ID")
    parser.add_argument("--hostname", default=None, help="Device hostname")
    args = parser.parse_args()

    result = enroll(args.device_id, args.hostname)

    print("\n" + "=" * 60)
    print("  ENDPOINT ENROLLED SUCCESSFULLY!")
    print("=" * 60)
    print(f"Device ID:   {result['device_id']}")
    print(f"One-Time Key: {result['api_key']}")
    print(f"DynamoDB:    {result['table']}")
    print("=" * 60)
    print("\nCopy this API key into your .env file:")
    print(f"API_KEY={result['api_key']}\n")


if __name__ == "__main__":
    main()
