"""Holder Proof creation and reference verification."""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

from .authority import capability_hash, request_hash
from .canonical import canonical_json
from .crypto import b64url_decode, b64url_encode, protocol_message, sign_sm2, verify_sm2
from .errors import VerificationError
from .keys import KeyRegistry
from .models import AgentRequest, HolderProof, HolderProofBody, ProtocolSignature, SignedCapability

HOLDER_PROOF_DOMAIN = "HOLDER_PROOF"


def new_challenge() -> str:
    """Reference helper; production challenges are issued and consumed by Broker."""

    return secrets.token_hex(16)


def create_holder_proof(
    capability: SignedCapability,
    request: AgentRequest,
    challenge: str,
    *,
    agent_private_key: Any,
    now: int | None = None,
    lifetime_seconds: int = 30,
) -> HolderProof:
    issued_at = int(time.time()) if now is None else now
    if not 1 <= lifetime_seconds <= 60:
        raise ValueError("holder proof lifetime must be between 1 and 60 seconds")
    body = capability.body
    actual_hash = request_hash(request)
    if actual_hash != body.request_hash:
        raise VerificationError("REQUEST_HASH_MISMATCH", "refusing to prove a request not bound to capability")
    if (
        request.agent_id != body.agent_id
        or request.agent_key_id != body.agent_key_id
        or request.task_id != body.task_id
    ):
        raise VerificationError("HOLDER_BINDING_MISMATCH", "request identity/task differs from capability")
    proof_body = HolderProofBody(
        proof_id=f"proof_{uuid.uuid4().hex}",
        capability_id=body.capability_id,
        capability_hash=capability_hash(capability),
        agent_id=body.agent_id,
        agent_key_id=body.agent_key_id,
        audience=body.audience,
        request_hash=actual_hash,
        challenge=challenge,
        issued_at=issued_at,
        expires_at=issued_at + lifetime_seconds,
    )
    message = protocol_message(HOLDER_PROOF_DOMAIN, canonical_json(proof_body))
    signature = ProtocolSignature(
        key_id=body.agent_key_id,
        value=b64url_encode(sign_sm2(agent_private_key, message)),
    )
    return HolderProof(body=proof_body, signature=signature)


class HolderProofVerifier:
    def __init__(self, key_registry: KeyRegistry, *, clock: Any = time.time, clock_skew_seconds: int = 5) -> None:
        self.key_registry = key_registry
        self.clock = clock
        self.clock_skew_seconds = clock_skew_seconds

    def verify(
        self,
        proof: HolderProof,
        capability: SignedCapability,
        request: AgentRequest,
        *,
        expected_challenge: str,
        expected_audience: str,
        now: int | None = None,
    ) -> None:
        body = proof.body
        cap = capability.body
        current = int(self.clock()) if now is None else now
        if proof.signature.key_id != body.agent_key_id:
            raise VerificationError("SIGNATURE_KEY_MISMATCH", "proof signature key differs from body")
        if body.challenge != expected_challenge:
            raise VerificationError("CHALLENGE_MISMATCH", "Holder Proof challenge does not match")
        if body.audience != expected_audience or cap.audience != expected_audience:
            raise VerificationError("AUDIENCE_MISMATCH", "Holder Proof audience does not match Broker")
        if current + self.clock_skew_seconds < body.issued_at:
            raise VerificationError("PROOF_NOT_YET_VALID", "Holder Proof issued_at is in the future")
        if current >= body.expires_at:
            raise VerificationError("PROOF_EXPIRED", "Holder Proof has expired")
        actual_hash = request_hash(request)
        if (
            body.capability_id != cap.capability_id
            or body.capability_hash != capability_hash(capability)
            or body.request_hash != actual_hash
            or body.request_hash != cap.request_hash
            or body.agent_id != cap.agent_id
            or body.agent_key_id != cap.agent_key_id
        ):
            raise VerificationError("HOLDER_BINDING_MISMATCH", "Holder Proof bindings do not match")
        public_key = self.key_registry.get_public_key(
            body.agent_key_id,
            purpose="HOLDER_PROOF",
            subject_id=body.agent_id,
            at_time=body.issued_at,
        )
        message = protocol_message(HOLDER_PROOF_DOMAIN, canonical_json(body))
        verify_sm2(public_key, message, b64url_decode(proof.signature.value))
