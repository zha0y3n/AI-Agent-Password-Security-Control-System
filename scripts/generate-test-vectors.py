#!/usr/bin/env python3
"""Generate non-production SM2/SM3 interoperability vectors.

This script intentionally writes a test-only private scalar so Go can perform
round-trip signing tests. Never reuse the generated key outside tests.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_aa.canonical import canonical_json
from agent_aa.crypto import (
    SM2_USER_ID,
    b64url_encode,
    generate_sm2_private_key,
    protocol_message,
    public_key_to_pem,
    sign_sm2,
    sm3_hex,
)
from agent_aa.authority import capability_hash
from agent_aa.models import (
    AgentRequest,
    CapabilityBody,
    ExecutionReceipt,
    HolderProofBody,
    ProtocolSignature,
    SignedCapability,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "shared" / "test-vectors" / "sm2-sm3-v1.json"


def main() -> None:
    request = AgentRequest(
        request_id="req-vector-001",
        agent_id="agent-vector-01",
        agent_key_id="agent-key-vector-01",
        task_id="task-vector-001",
        service="git",
        resource="repo/course-project",
        operation="read_file",
        method="GET",
        path="/repos/course-project/files/README.md",
        query={"ref": "main"},
        body=None,
        credential_id="github-prod",
    )
    request_bytes = canonical_json(request)
    capability = CapabilityBody(
        capability_id="cap-vector-001",
        issuer="aa-vector-01",
        issuer_key_id="aa-key-vector-01",
        audience="broker-01",
        agent_id=request.agent_id,
        agent_key_id=request.agent_key_id,
        task_id=request.task_id,
        service=request.service,
        resource=request.resource,
        operation=request.operation,
        request_hash=sm3_hex(request_bytes),
        credential_id=request.credential_id,
        credential_epoch=17,
        issued_at=1_800_000_000,
        expires_at=1_800_000_060,
        ttl_seconds=60,
        nonce="00112233445566778899aabbccddeeff",
    )
    payload = canonical_json(capability)
    message = protocol_message("CAPABILITY", payload)
    aa_key = generate_sm2_private_key()
    private_numbers = aa_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    signature = sign_sm2(aa_key, message)
    signed_capability = SignedCapability(
        body=capability,
        signature=ProtocolSignature(
            key_id=capability.issuer_key_id,
            value=b64url_encode(signature),
        ),
    )

    agent_key = generate_sm2_private_key()
    agent_private_numbers = agent_key.private_numbers()
    agent_public_numbers = agent_private_numbers.public_numbers
    holder_body = HolderProofBody(
        proof_id="proof-vector-001",
        capability_id=capability.capability_id,
        capability_hash=capability_hash(signed_capability),
        agent_id=capability.agent_id,
        agent_key_id=capability.agent_key_id,
        audience=capability.audience,
        request_hash=capability.request_hash,
        challenge="ffeeddccbbaa99887766554433221100",
        issued_at=1_800_000_001,
        expires_at=1_800_000_031,
    )
    holder_payload = canonical_json(holder_body)
    holder_message = protocol_message("HOLDER_PROOF", holder_payload)
    holder_signature = sign_sm2(agent_key, holder_message)

    broker_key = generate_sm2_private_key()
    broker_private_numbers = broker_key.private_numbers()
    broker_public_numbers = broker_private_numbers.public_numbers
    receipt_body = ExecutionReceipt(
        receipt_id="receipt-vector-001",
        broker_id="broker-01",
        broker_key_id="broker-key-vector-01",
        capability_id=capability.capability_id,
        request_hash=capability.request_hash,
        credential_id=capability.credential_id,
        credential_epoch=capability.credential_epoch,
        result_hash=sm3_hex(canonical_json({"content": "README vector result", "status": 200})),
        outcome="SUCCESS",
        executed_at=1_800_000_010,
    )
    receipt_payload = canonical_json(receipt_body)
    receipt_message = protocol_message("EXECUTION_RECEIPT", receipt_payload)
    receipt_signature = sign_sm2(broker_key, receipt_message)
    document = {
        "warning": "TEST-ONLY PRIVATE KEY - NEVER USE IN PRODUCTION",
        "protocol_version": "1.0",
        "canonical_profile": "ZTCANON-JSON-v1",
        "signature_algorithm": "SM2-with-SM3 over raw domain-separated message",
        "signature_encoding": "ASN.1 DER sequence of INTEGER r and INTEGER s",
        "sm2_user_id_ascii": SM2_USER_ID.decode("ascii"),
        "domain_prefix_hex": b"AACRED\x00".hex(),
        "request": request.model_dump(mode="json"),
        "request_canonical_hex": request_bytes.hex(),
        "request_sm3_hex": sm3_hex(request_bytes),
        "capability_body": capability.model_dump(mode="json"),
        "capability_canonical_hex": payload.hex(),
        "signature_message_hex": message.hex(),
        "test_private_key_scalar_hex": f"{private_numbers.private_value:064x}",
        "public_key_uncompressed_hex": f"04{public_numbers.x:064x}{public_numbers.y:064x}",
        "public_key_spki_pem": public_key_to_pem(aa_key.public_key()).decode("ascii"),
        "signature_der_hex": signature.hex(),
        "holder_proof_vector": {
            "body": holder_body.model_dump(mode="json"),
            "canonical_hex": holder_payload.hex(),
            "signature_message_hex": holder_message.hex(),
            "test_private_key_scalar_hex": f"{agent_private_numbers.private_value:064x}",
            "public_key_uncompressed_hex": f"04{agent_public_numbers.x:064x}{agent_public_numbers.y:064x}",
            "public_key_spki_pem": public_key_to_pem(agent_key.public_key()).decode("ascii"),
            "signature_der_hex": holder_signature.hex(),
        },
        "receipt_vector": {
            "body": receipt_body.model_dump(mode="json"),
            "canonical_hex": receipt_payload.hex(),
            "signature_message_hex": receipt_message.hex(),
            "test_private_key_scalar_hex": f"{broker_private_numbers.private_value:064x}",
            "public_key_uncompressed_hex": f"04{broker_public_numbers.x:064x}{broker_public_numbers.y:064x}",
            "public_key_spki_pem": public_key_to_pem(broker_key.public_key()).decode("ascii"),
            "signature_der_hex": receipt_signature.hex(),
        },
        "sm3_known_answer": {
            "message_hex": b"abc".hex(),
            "digest_hex": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
