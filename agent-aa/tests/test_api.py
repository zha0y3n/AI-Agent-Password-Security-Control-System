from __future__ import annotations

import json

from fastapi.testclient import TestClient

from agent_aa.api import create_app
from agent_aa.models import ExecutionReceipt
from agent_aa.receipt import sign_receipt


def test_issue_api_and_health(protocol_env) -> None:
    env = protocol_env
    client = TestClient(create_app(env["authority"], env["registry"]))
    assert client.get("/health").json()["status"] == "ok"
    response = client.post(
        "/v1/capabilities/issue",
        json={"request": env["request"].model_dump(mode="json"), "ttl_seconds": 60},
    )
    assert response.status_code == 200, response.text
    assert response.json()["body"]["audience"] == "broker-01"


def test_issue_api_denies_untrusted_request(protocol_env) -> None:
    env = protocol_env
    client = TestClient(create_app(env["authority"], env["registry"]))
    request = env["request"].model_copy(update={"resource": "repo/private"})
    response = client.post(
        "/v1/capabilities/issue",
        json={"request": request.model_dump(mode="json"), "ttl_seconds": 60},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "REQUEST_NOT_AUTHORIZED"


def test_api_rejects_duplicate_json_field(protocol_env) -> None:
    env = protocol_env
    client = TestClient(create_app(env["authority"], env["registry"]))
    request_json = json.dumps(env["request"].model_dump(mode="json"), separators=(",", ":"))
    raw = '{"request":' + request_json + ',"ttl_seconds":60,"ttl_seconds":30}'
    response = client.post(
        "/v1/capabilities/issue",
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "CANONICALIZATION_ERROR"


def test_receipt_verify_api(protocol_env) -> None:
    env = protocol_env
    client = TestClient(create_app(env["authority"], env["registry"]))
    receipt = ExecutionReceipt(
        receipt_id="receipt-api-001",
        broker_id="broker-01",
        broker_key_id="broker-key-test-01",
        capability_id="cap-api-001",
        request_hash="11" * 32,
        credential_id="github-prod",
        credential_epoch=17,
        result_hash="22" * 32,
        outcome="SUCCESS",
        executed_at=env["now"],
    )
    signed = sign_receipt(receipt, broker_private_key=env["broker_key"])
    response = client.post(
        "/v1/receipts/verify",
        json={"receipt": signed.model_dump(mode="json"), "expected_broker_id": "broker-01"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"valid": True, "code": "OK"}
