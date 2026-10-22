"""Unit tests for Lambda Authorizer."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest
from authorizer import (
    find_device_by_key_hash,
    handler,
    hash_api_key,
)


@pytest.fixture
def mock_dynamodb():
    mock_dyn = MagicMock()
    mock_table = MagicMock()
    mock_dyn.Table.return_value = mock_table
    return mock_dyn, mock_table


def test_hash_api_key():
    raw_key = "secret-token-123"
    expected = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    assert hash_api_key(raw_key) == expected


def test_find_device_by_key_hash_direct_hint(mock_dynamodb):
    _, mock_table = mock_dynamodb
    key_hash = hash_api_key("valid-key")
    device_record = {
        "device_id": "PC-LAB-01",
        "api_key_hash": key_hash,
        "status": "Online",
    }
    mock_table.get_item.return_value = {"Item": device_record}

    res = find_device_by_key_hash(mock_table, key_hash, device_id_hint="PC-LAB-01")
    assert res == device_record
    mock_table.get_item.assert_called_once_with(Key={"device_id": "PC-LAB-01"})


def test_find_device_by_key_hash_gsi(mock_dynamodb):
    _, mock_table = mock_dynamodb
    mock_table.get_item.return_value = {}  # Direct lookup fails or no hint
    key_hash = hash_api_key("valid-key")
    device_record = {
        "device_id": "PC-LAB-01",
        "api_key_hash": key_hash,
        "status": "Online",
    }
    mock_table.query.return_value = {"Items": [device_record]}

    res = find_device_by_key_hash(mock_table, key_hash)
    assert res == device_record
    assert mock_table.query.called


def test_authorizer_missing_key(mock_dynamodb):
    mock_dyn, _ = mock_dynamodb
    event = {
        "version": "2.0",
        "headers": {},
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["isAuthorized"] is False


def test_authorizer_unknown_key(mock_dynamodb):
    mock_dyn, mock_table = mock_dynamodb
    mock_table.get_item.return_value = {}
    mock_table.query.return_value = {"Items": []}
    mock_table.scan.return_value = {"Items": []}

    event = {
        "version": "2.0",
        "headers": {"x-api-key": "unknown-token"},
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["isAuthorized"] is False


def test_authorizer_valid_key_online(mock_dynamodb):
    mock_dyn, mock_table = mock_dynamodb
    key_hash = hash_api_key("valid-secret-key")
    device_record = {
        "device_id": "PC-LAB-01",
        "api_key_hash": key_hash,
        "status": "Online",
    }
    mock_table.get_item.return_value = {"Item": device_record}

    event = {
        "version": "2.0",
        "headers": {
            "x-api-key": "valid-secret-key",
            "x-device-id": "PC-LAB-01",
        },
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["isAuthorized"] is True
    assert resp["context"]["deviceId"] == "PC-LAB-01"
    assert resp["context"]["status"] == "Online"


def test_authorizer_case_insensitive_header(mock_dynamodb):
    mock_dyn, mock_table = mock_dynamodb
    key_hash = hash_api_key("valid-secret-key")
    device_record = {
        "device_id": "PC-LAB-01",
        "api_key_hash": key_hash,
        "status": "Online",
    }
    mock_table.get_item.return_value = {"Item": device_record}

    event = {
        "version": "2.0",
        "headers": {
            "X-Api-Key": "valid-secret-key",
            "X-Device-Id": "PC-LAB-01",
        },
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["isAuthorized"] is True
    assert resp["context"]["deviceId"] == "PC-LAB-01"


def test_authorizer_revoked_device(mock_dynamodb):
    mock_dyn, mock_table = mock_dynamodb
    key_hash = hash_api_key("revoked-key")
    device_record = {
        "device_id": "PC-REVOKED",
        "api_key_hash": key_hash,
        "status": "Revoked",
    }
    mock_table.get_item.return_value = {"Item": device_record}

    event = {
        "version": "2.0",
        "headers": {
            "x-api-key": "revoked-key",
            "x-device-id": "PC-REVOKED",
        },
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["isAuthorized"] is False


def test_authorizer_iam_policy_v1_format(mock_dynamodb):
    mock_dyn, mock_table = mock_dynamodb
    key_hash = hash_api_key("valid-key")
    device_record = {
        "device_id": "PC-LAB-01",
        "api_key_hash": key_hash,
        "status": "Online",
    }
    mock_table.get_item.return_value = {"Item": device_record}

    event = {
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api-id/dev/POST/events",
        "headers": {
            "x-api-key": "valid-key",
            "x-device-id": "PC-LAB-01",
        },
    }
    resp = handler(event, dynamodb_resource=mock_dyn)
    assert resp["principalId"] == "PC-LAB-01"
    assert resp["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    assert resp["context"]["deviceId"] == "PC-LAB-01"
