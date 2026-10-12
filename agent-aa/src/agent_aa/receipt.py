"""Execution Receipt format, reference signer, and verifier.

The production signer belongs to the Go Broker. The signer here exists for
cross-language vectors and isolated protocol tests only.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json
from .crypto import b64url_decode, b64url_encode, protocol_message, sign_sm2, verify_sm2
from .errors import VerificationError
from .keys import KeyRegistry
from .models import ExecutionReceipt, ProtocolSignature, SignedReceipt

RECEIPT_DOMAIN = "EXECUTION_RECEIPT"


def sign_receipt(receipt: ExecutionReceipt, *, broker_private_key: Any) -> SignedReceipt:
    message = protocol_message(RECEIPT_DOMAIN, canonical_json(receipt))
    return SignedReceipt(
        body=receipt,
        signature=ProtocolSignature(
            key_id=receipt.broker_key_id,
            value=b64url_encode(sign_sm2(broker_private_key, message)),
        ),
    )


class ReceiptVerifier:
    def __init__(self, key_registry: KeyRegistry) -> None:
        self.key_registry = key_registry

    def verify(self, receipt: SignedReceipt, *, expected_broker_id: str) -> None:
        body = receipt.body
        if body.broker_id != expected_broker_id:
            raise VerificationError("BROKER_MISMATCH", "receipt was issued by another Broker")
        if receipt.signature.key_id != body.broker_key_id:
            raise VerificationError("SIGNATURE_KEY_MISMATCH", "receipt signature key differs from body")
        public_key = self.key_registry.get_public_key(
            body.broker_key_id,
            purpose="RECEIPT_SIGNING",
            subject_id=body.broker_id,
            at_time=body.executed_at,
        )
        message = protocol_message(RECEIPT_DOMAIN, canonical_json(body))
        verify_sm2(public_key, message, b64url_decode(receipt.signature.value))
