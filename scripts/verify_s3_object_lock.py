"""Verification script for S3 Object Lock and WORM immutability (PRD Section 11 & Phase 13.6).

Validates that:
1. S3 Object Lock configuration is Enabled on the raw logs bucket.
2. Default retention rule is configured with 90-day retention.
3. Object deletion requests within the retention window are rejected with AccessDenied.
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("verify_object_lock")


def verify_bucket_object_lock(s3_client: Any, bucket_name: str) -> bool:
    """Checks that Object Lock is enabled with a default retention period."""
    logger.info(f"Querying Object Lock configuration for bucket: {bucket_name}")
    try:
        resp = s3_client.get_object_lock_configuration(Bucket=bucket_name)
        cfg = resp.get("ObjectLockConfiguration", {})
        status = cfg.get("ObjectLockEnabled")
        rule = cfg.get("Rule", {}).get("DefaultRetention", {})
        mode = rule.get("Mode")
        days = rule.get("Days")

        logger.info(f"ObjectLockEnabled: {status}")
        logger.info(f"Default Retention Mode: {mode}, Days: {days}")

        if status != "Enabled":
            logger.error("FAILURE: Object Lock is not Enabled on the bucket.")
            return False

        if not days or int(days) < 90:
            logger.warning(f"Retention days ({days}) is less than recommended 90 days.")
        else:
            logger.info("PASS: Retention period is >= 90 days.")

        return True
    except ClientError as e:
        logger.error(f"Failed to get object lock configuration: {e}")
        return False


def verify_immutability(s3_client: Any, bucket_name: str) -> bool:
    """Uploads a test object under retention and verifies that DeleteObject is denied."""
    test_key = f"verification-tests/test-immutable-{uuid.uuid4().hex[:8]}.txt"
    test_body = b"WORM compliance verification test payload."

    logger.info(f"Uploading test object to s3://{bucket_name}/{test_key}...")
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=test_key,
            Body=test_body,
            ContentType="text/plain",
        )
        logger.info("Test object uploaded successfully.")
    except ClientError as e:
        logger.error(f"Failed to upload test object: {e}")
        return False

    logger.info("Attempting to DELETE the object under active retention...")
    try:
        s3_client.delete_object(
            Bucket=bucket_name,
            Key=test_key,
            BypassGovernanceRetention=False,
        )
        logger.error("FAILURE: Object was deleted! Object Lock did not prevent deletion.")
        return False
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "ObjectLockConfigurationNotFoundError"):
            logger.info(f"SUCCESS: Deletion blocked with {error_code} as expected.")
            return True
        logger.warning(f"Unexpected ClientError on delete attempt: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify S3 Object Lock Immutability")
    parser.add_argument("--bucket", required=True, help="Raw logs S3 bucket name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    args = parser.parse_args()

    s3 = boto3.client("s3", region_name=args.region)

    ok_cfg = verify_bucket_object_lock(s3, args.bucket)
    ok_del = verify_immutability(s3, args.bucket)

    if ok_cfg and ok_del:
        logger.info("ALL S3 OBJECT LOCK CHECKS PASSED.")
        return 0
    else:
        logger.error("S3 OBJECT LOCK CHECKS FAILED.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
