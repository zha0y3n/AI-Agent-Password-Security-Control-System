from __future__ import annotations

import pytest

from agent_aa.errors import VerificationError
from agent_aa.models import ExecutionReceipt
from agent_aa.receipt import ReceiptVerifier, sign_receipt


def test_receipt_sign_and_verify(protocol_env) -> None:
    env = protocol_env
    receipt = ExecutionReceipt(
        receipt_id="receipt-test-001",
        broker_id="broker-01",
        broker_key_id="broker-key-test-01",
        capability_id="cap-test-001",
        request_hash="11" * 32,
        credential_id="github-prod",
        credential_epoch=17,
        result_hash="22" * 32,
        outcome="SUCCESS",
        executed_at=env["now"],
    )
    signed = sign_receipt(receipt, broker_private_key=env["broker_key"])
    ReceiptVerifier(env["registry"]).verify(signed, expected_broker_id="broker-01")


def test_receipt_tamper_fails(protocol_env) -> None:
    env = protocol_env
    receipt = ExecutionReceipt(
        receipt_id="receipt-test-001",
        broker_id="broker-01",
        broker_key_id="broker-key-test-01",
        capability_id="cap-test-001",
        request_hash="11" * 32,
        credential_id="github-prod",
        credential_epoch=17,
        result_hash="22" * 32,
        outcome="SUCCESS",
        executed_at=env["now"],
    )
    signed = sign_receipt(receipt, broker_private_key=env["broker_key"])
    tampered = signed.model_copy(update={"body": receipt.model_copy(update={"result_hash": "33" * 32})})
    with pytest.raises(VerificationError) as caught:
        ReceiptVerifier(env["registry"]).verify(tampered, expected_broker_id="broker-01")
    assert caught.value.code == "INVALID_SIGNATURE"
