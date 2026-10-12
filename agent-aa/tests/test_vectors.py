from __future__ import annotations

import json
from pathlib import Path

from tongsuopy.crypto.asymciphers import ec

from agent_aa.canonical import canonical_json
from agent_aa.crypto import sm3_hex, verify_sm2
from agent_aa.models import AgentRequest, CapabilityBody, ExecutionReceipt, HolderProofBody

VECTOR = Path(__file__).resolve().parents[2] / "shared" / "test-vectors" / "sm2-sm3-v1.json"


def test_cross_language_vector_is_self_consistent() -> None:
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    request = AgentRequest.model_validate(vector["request"])
    capability = CapabilityBody.model_validate(vector["capability_body"])
    assert canonical_json(request).hex() == vector["request_canonical_hex"]
    assert sm3_hex(canonical_json(request)) == vector["request_sm3_hex"]
    assert canonical_json(capability).hex() == vector["capability_canonical_hex"]
    assert bytes.fromhex(vector["signature_message_hex"]).endswith(canonical_json(capability))
    point = bytes.fromhex(vector["public_key_uncompressed_hex"])
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SM2()).public_key()
    verify_sm2(
        public_key,
        bytes.fromhex(vector["signature_message_hex"]),
        bytes.fromhex(vector["signature_der_hex"]),
    )


def test_vector_sm3_known_answer() -> None:
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    known = vector["sm3_known_answer"]
    assert sm3_hex(bytes.fromhex(known["message_hex"])) == known["digest_hex"]


def _verify_nested_vector(vector: dict, model_type: type) -> None:
    body = model_type.model_validate(vector["body"])
    assert canonical_json(body).hex() == vector["canonical_hex"]
    point = bytes.fromhex(vector["public_key_uncompressed_hex"])
    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(point[1:33], "big"),
        int.from_bytes(point[33:65], "big"),
        ec.SM2(),
    ).public_key()
    verify_sm2(
        public_key,
        bytes.fromhex(vector["signature_message_hex"]),
        bytes.fromhex(vector["signature_der_hex"]),
    )


def test_holder_and_receipt_vectors() -> None:
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    _verify_nested_vector(vector["holder_proof_vector"], HolderProofBody)
    _verify_nested_vector(vector["receipt_vector"], ExecutionReceipt)
