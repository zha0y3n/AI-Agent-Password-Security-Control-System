"""Authorization Authority capability issuance and reference verification."""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

from .canonical import canonical_json
from .crypto import b64url_decode, b64url_encode, protocol_message, sign_sm2, sm3_hex, verify_sm2
from .errors import AuthorizationDenied, VerificationError
from .keys import KeyRegistry
from .models import AgentRequest, CapabilityBody, ProtocolSignature, SignedCapability
from .policy import AuthorizationPolicy

CAPABILITY_DOMAIN = "CAPABILITY"


def request_hash(request: AgentRequest) -> str:
    return sm3_hex(canonical_json(request))


def capability_hash(capability: SignedCapability) -> str:
    return sm3_hex(canonical_json(capability))


class AuthorizationAuthority:
    def __init__(
        self,
        *,
        issuer_id: str,
        issuer_key_id: str,
        private_key: Any,
        policy: AuthorizationPolicy,
        key_registry: KeyRegistry,
        clock: Any = time.time,
    ) -> None:
        self.issuer_id = issuer_id
        self.issuer_key_id = issuer_key_id
        self.private_key = private_key
        self.policy = policy
        self.key_registry = key_registry
        self.clock = clock

    def issue_capability(
        self,
        request: AgentRequest,
        *,
        ttl_seconds: int = 60,
        now: int | None = None,
    ) -> SignedCapability:
        """Issue only after an exact match against server-owned trusted context."""

        issued_at = int(self.clock()) if now is None else now
        action = self.policy.authorize(request, ttl_seconds=ttl_seconds, now=issued_at)
        self.key_registry.get_record(
            request.agent_key_id,
            purpose="HOLDER_PROOF",
            subject_id=request.agent_id,
            at_time=issued_at,
        )
        self.key_registry.get_record(
            self.issuer_key_id,
            purpose="CAPABILITY_SIGNING",
            subject_id=self.issuer_id,
            at_time=issued_at,
        )
        body = CapabilityBody(
            capability_id=f"cap_{uuid.uuid4().hex}",
            issuer=self.issuer_id,
            issuer_key_id=self.issuer_key_id,
            audience=action.audience,
            agent_id=request.agent_id,
            agent_key_id=request.agent_key_id,
            task_id=request.task_id,
            service=request.service,
            resource=request.resource,
            operation=request.operation,
            request_hash=request_hash(request),
            credential_id=action.credential_id,
            credential_epoch=action.credential_epoch,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            ttl_seconds=ttl_seconds,
            nonce=secrets.token_hex(16),
        )
        message = protocol_message(CAPABILITY_DOMAIN, canonical_json(body))
        signature = ProtocolSignature(
            key_id=self.issuer_key_id,
            value=b64url_encode(sign_sm2(self.private_key, message)),
        )
        return SignedCapability(body=body, signature=signature)


class CapabilityVerifier:
    """Python reference verifier for Broker interoperability and A-side tests."""

    def __init__(
        self,
        key_registry: KeyRegistry,
        *,
        trusted_issuer: str,
        clock: Any = time.time,
        clock_skew_seconds: int = 5,
    ) -> None:
        self.key_registry = key_registry
        self.trusted_issuer = trusted_issuer
        self.clock = clock
        self.clock_skew_seconds = clock_skew_seconds

    def verify(
        self,
        capability: SignedCapability,
        request: AgentRequest,
        *,
        expected_audience: str,
        now: int | None = None,
    ) -> None:
        body = capability.body
        current = int(self.clock()) if now is None else now
        if body.issuer != self.trusted_issuer:
            raise VerificationError("UNTRUSTED_ISSUER", "capability issuer is not trusted")
        if capability.signature.key_id != body.issuer_key_id:
            raise VerificationError("SIGNATURE_KEY_MISMATCH", "signature key id differs from signed body")
        public_key = self.key_registry.get_public_key(
            body.issuer_key_id,
            purpose="CAPABILITY_SIGNING",
            subject_id=body.issuer,
            at_time=body.issued_at,
        )
        message = protocol_message(CAPABILITY_DOMAIN, canonical_json(body))
        verify_sm2(public_key, message, b64url_decode(capability.signature.value))
        if current + self.clock_skew_seconds < body.issued_at:
            raise VerificationError("CAPABILITY_NOT_YET_VALID", "capability issued_at is in the future")
        if current >= body.expires_at:
            raise VerificationError("CAPABILITY_EXPIRED", "capability has expired")
        if body.audience != expected_audience:
            raise VerificationError("AUDIENCE_MISMATCH", "capability audience does not match this Broker")
        if (
            body.agent_id != request.agent_id
            or body.agent_key_id != request.agent_key_id
            or body.task_id != request.task_id
            or body.service != request.service
            or body.resource != request.resource
            or body.operation != request.operation
            or body.credential_id != request.credential_id
        ):
            raise VerificationError("REQUEST_BINDING_MISMATCH", "request fields differ from the capability")
        if body.request_hash != request_hash(request):
            raise VerificationError("REQUEST_HASH_MISMATCH", "canonical request hash differs from capability")


def require_authorized_issue(authority: AuthorizationAuthority, request: AgentRequest, ttl_seconds: int) -> SignedCapability:
    """Small explicit boundary used by API/CLI; all failures propagate closed."""

    try:
        return authority.issue_capability(request, ttl_seconds=ttl_seconds)
    except (AuthorizationDenied, VerificationError):
        raise
