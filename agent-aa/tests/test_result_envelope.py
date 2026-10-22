from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_aa.canonical import canonical_json
from agent_aa.crypto import sm3_hex
from agent_aa.errors import VerificationError
from agent_aa.models import ExecutionReceipt, ResultEnvelope
from agent_aa.receipt import ReceiptVerifier, sign_receipt

VECTOR = Path(__file__).resolve().parents[2] / "shared" / "test-vectors" / "result-envelope-v1.json"


def _envelope(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "1.0",
        "capability_id": "cap-test-001",
        "request_hash": "11" * 32,
        "outcome": "SUCCESS",
        "code": None,
        "upstream_status": 200,
        "upstream_body": {"content": "hello"},
    }
    value.update(overrides)
    return value


def test_result_envelope_vectors_are_self_consistent() -> None:
    document = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert document["vectors"]
    for vector in document["vectors"]:
        envelope = ResultEnvelope.model_validate(vector["envelope"])
        canonical = canonical_json(envelope)
        assert canonical.hex() == vector["canonical_hex"], vector["name"]
        assert sm3_hex(canonical) == vector["result_hash"], vector["name"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"code": "UPSTREAM_REJECTED"},  # SUCCESS with a code
        {"upstream_status": None, "upstream_body": None},  # SUCCESS without reaching upstream
        {"outcome": "ERROR"},  # ERROR without a code
        {"outcome": "DENIED", "code": "CHALLENGE_USED"},  # DENIED that reached upstream
        {"outcome": "ERROR", "code": "UPSTREAM_ERROR", "upstream_status": None},  # body without status
        {"upstream_status": 99},
        {"code": "lowercase", "outcome": "ERROR"},
        {"upstream_body": 1.5},  # floats are not ZTCANON-JSON-v1
        {"extra": True},
    ],
)
def test_result_envelope_rejects_inconsistent_results(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ResultEnvelope.model_validate(_envelope(**overrides))


def _signed(env: dict[str, object], envelope: ResultEnvelope, **overrides: object):
    body = {
        "receipt_id": "receipt-test-001",
        "broker_id": "broker-01",
        "broker_key_id": "broker-key-test-01",
        "capability_id": envelope.capability_id,
        "request_hash": envelope.request_hash,
        "credential_id": "github-prod",
        "credential_epoch": 17,
        "result_hash": sm3_hex(canonical_json(envelope)),
        "outcome": envelope.outcome,
        "executed_at": env["now"],
    }
    body.update(overrides)
    return sign_receipt(ExecutionReceipt(**body), broker_private_key=env["broker_key"])


def test_verify_result_accepts_the_bound_envelope(protocol_env) -> None:
    envelope = ResultEnvelope.model_validate(_envelope())
    ReceiptVerifier(protocol_env["registry"]).verify_result(
        _signed(protocol_env, envelope), envelope, expected_broker_id="broker-01"
    )


@pytest.mark.parametrize(
    "tamper",
    [
        {"upstream_body": {"content": "forged"}},
        {"capability_id": "cap-test-002"},
        {"request_hash": "33" * 32},
    ],
)
def test_verify_result_rejects_another_envelope(protocol_env, tamper: dict[str, object]) -> None:
    envelope = ResultEnvelope.model_validate(_envelope())
    signed = _signed(protocol_env, envelope)
    with pytest.raises(VerificationError) as caught:
        ReceiptVerifier(protocol_env["registry"]).verify_result(
            signed, ResultEnvelope.model_validate(_envelope(**tamper)), expected_broker_id="broker-01"
        )
    assert caught.value.code == "RESULT_BINDING_MISMATCH"


def test_verify_result_rejects_outcome_mismatch(protocol_env) -> None:
    envelope = ResultEnvelope.model_validate(_envelope())
    # A correctly signed receipt whose outcome disagrees with the envelope it hashes.
    signed = _signed(protocol_env, envelope, outcome="ERROR")
    with pytest.raises(VerificationError) as caught:
        ReceiptVerifier(protocol_env["registry"]).verify_result(signed, envelope, expected_broker_id="broker-01")
    assert caught.value.code == "RESULT_BINDING_MISMATCH"
