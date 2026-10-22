"""Strict protocol and trusted-policy data models."""

from __future__ import annotations

import base64
import re
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import TypeAliasType

Identifier = Annotated[str, Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")]
HashHex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
NonceHex = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
ChallengeHex = Annotated[str, Field(pattern=r"^[0-9a-f]{32,64}$")]
Timestamp = Annotated[int, Field(ge=0, le=2**63 - 1)]
PositiveEpoch = Annotated[int, Field(ge=1, le=2**31 - 1)]
QueryValue: TypeAlias = str | list[str]
JsonValue = TypeAliasType(
    "JsonValue",
    None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"],
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AgentRequest(StrictModel):
    """The exact action envelope hashed into a capability."""

    protocol_version: Literal["1.0"] = "1.0"
    request_id: Identifier
    agent_id: Identifier
    agent_key_id: Identifier
    task_id: Identifier
    service: Identifier
    resource: Identifier
    operation: Identifier
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    query: dict[str, QueryValue] = Field(default_factory=dict)
    body: JsonValue = None
    credential_id: Identifier

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or "\\" in value or "\x00" in value:
            raise ValueError("path must be an absolute slash path without NUL or backslash")
        if any(segment in {".", ".."} for segment in value.split("/")):
            raise ValueError("dot path segments are forbidden")
        return value

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: dict[str, QueryValue]) -> dict[str, QueryValue]:
        key_pattern = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
        for key, item in value.items():
            if not key_pattern.fullmatch(key):
                raise ValueError(f"invalid query key: {key!r}")
            if isinstance(item, list) and not item:
                raise ValueError("query arrays must not be empty")
        return value

    @field_validator("body")
    @classmethod
    def validate_body_profile(cls, value: JsonValue) -> JsonValue:
        from .canonical import canonical_json

        canonical_json(value)
        return value


class AllowedAction(StrictModel):
    """An exact request template loaded from a trusted task store."""

    service: Identifier
    resource: Identifier
    operation: Identifier
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    query: dict[str, QueryValue] = Field(default_factory=dict)
    body: JsonValue = None
    credential_id: Identifier
    credential_epoch: PositiveEpoch
    audience: Identifier
    max_ttl_seconds: Annotated[int, Field(ge=1, le=300)] = 60

    @field_validator("body")
    @classmethod
    def validate_body_profile(cls, value: JsonValue) -> JsonValue:
        from .canonical import canonical_json

        canonical_json(value)
        return value


class CredentialStatus(StrictModel):
    """Public, non-secret Credential metadata returned by the trusted Broker.

    This is deliberately separate from ``AllowedAction``: the task store
    authorizes *which* credential may be used, while the Broker remains the
    authority for its current lifecycle state and epoch.
    """

    credential_id: Identifier
    provider: Identifier
    status: Literal["ACTIVE", "DISABLED", "REVOKED", "COMPROMISED", "DESTROYED"]
    credential_epoch: PositiveEpoch
    created_at: Timestamp
    updated_at: Timestamp

    @model_validator(mode="after")
    def validate_timestamps(self) -> "CredentialStatus":
        if self.updated_at < self.created_at:
            raise ValueError("credential updated_at must not precede created_at")
        return self


class TaskContext(StrictModel):
    """AA-owned context; it is never accepted from the Agent as authority."""

    protocol_version: Literal["1.0"] = "1.0"
    context_id: Identifier
    issuer: Identifier
    task_id: Identifier
    agent_id: Identifier
    agent_key_id: Identifier
    status: Literal["ACTIVE", "CANCELLED", "COMPLETED"]
    valid_from: Timestamp
    expires_at: Timestamp
    allowed_actions: list[AllowedAction] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_window(self) -> "TaskContext":
        if self.expires_at <= self.valid_from:
            raise ValueError("task expires_at must be after valid_from")
        return self


class CapabilityBody(StrictModel):
    protocol_version: Literal["1.0"] = "1.0"
    capability_id: Identifier
    issuer: Identifier
    issuer_key_id: Identifier
    audience: Identifier
    agent_id: Identifier
    agent_key_id: Identifier
    task_id: Identifier
    service: Identifier
    resource: Identifier
    operation: Identifier
    request_hash: HashHex
    credential_id: Identifier
    credential_epoch: PositiveEpoch
    issued_at: Timestamp
    expires_at: Timestamp
    ttl_seconds: Annotated[int, Field(ge=1, le=300)]
    nonce: NonceHex
    one_time: Literal[True] = True

    @model_validator(mode="after")
    def validate_times(self) -> "CapabilityBody":
        if self.expires_at <= self.issued_at:
            raise ValueError("capability expires_at must be after issued_at")
        if self.expires_at - self.issued_at != self.ttl_seconds:
            raise ValueError("ttl_seconds must equal expires_at - issued_at")
        return self


class ProtocolSignature(StrictModel):
    algorithm: Literal["SM2-SM3"] = "SM2-SM3"
    encoding: Literal["ASN.1-DER/base64url-nopad"] = "ASN.1-DER/base64url-nopad"
    sm2_user_id: Literal["1234567812345678"] = "1234567812345678"
    key_id: Identifier
    value: Annotated[str, Field(min_length=8, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")]

    @field_validator("value")
    @classmethod
    def validate_base64url(cls, value: str) -> str:
        try:
            base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("invalid base64url signature") from exc
        return value


class SignedCapability(StrictModel):
    body: CapabilityBody
    signature: ProtocolSignature


class HolderProofBody(StrictModel):
    protocol_version: Literal["1.0"] = "1.0"
    proof_id: Identifier
    capability_id: Identifier
    capability_hash: HashHex
    agent_id: Identifier
    agent_key_id: Identifier
    audience: Identifier
    request_hash: HashHex
    challenge: ChallengeHex
    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def validate_window(self) -> "HolderProofBody":
        if self.expires_at <= self.issued_at:
            raise ValueError("proof expires_at must be after issued_at")
        if self.expires_at - self.issued_at > 60:
            raise ValueError("holder proof lifetime may not exceed 60 seconds")
        return self


class HolderProof(StrictModel):
    body: HolderProofBody
    signature: ProtocolSignature


class ExecutionReceipt(StrictModel):
    protocol_version: Literal["1.0"] = "1.0"
    receipt_id: Identifier
    broker_id: Identifier
    broker_key_id: Identifier
    capability_id: Identifier
    request_hash: HashHex
    credential_id: Identifier
    credential_epoch: PositiveEpoch
    result_hash: HashHex
    outcome: Literal["SUCCESS", "DENIED", "ERROR"]
    executed_at: Timestamp


class SignedReceipt(StrictModel):
    body: ExecutionReceipt
    signature: ProtocolSignature


ErrorCode = Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")]


class ResultEnvelope(StrictModel):
    """The execution result whose ZTCANON-JSON-v1 SM3 digest is ``result_hash``.

    ``upstream_body`` is the upstream JSON value, or its raw text as a string
    when that JSON is not ZTCANON-JSON-v1 (for example, it contains floats).
    """

    protocol_version: Literal["1.0"] = "1.0"
    capability_id: Identifier
    request_hash: HashHex
    outcome: Literal["SUCCESS", "DENIED", "ERROR"]
    code: ErrorCode | None
    upstream_status: Annotated[int, Field(ge=100, le=599)] | None
    upstream_body: JsonValue

    @model_validator(mode="after")
    def validate_outcome(self) -> "ResultEnvelope":
        if (self.outcome == "SUCCESS") != (self.code is None):
            raise ValueError("only a SUCCESS result has no code")
        if self.outcome == "SUCCESS" and self.upstream_status is None:
            raise ValueError("a SUCCESS result must carry the upstream status")
        if self.outcome == "DENIED" and self.upstream_status is not None:
            raise ValueError("a DENIED result must not reach the upstream")
        if self.upstream_status is None and self.upstream_body is not None:
            raise ValueError("an upstream body requires an upstream status")
        return self


class PublicKeyRecord(StrictModel):
    key_id: Identifier
    subject_id: Identifier
    purpose: Literal["CAPABILITY_SIGNING", "HOLDER_PROOF", "RECEIPT_SIGNING"]
    algorithm: Literal["SM2"] = "SM2"
    status: Literal["ACTIVE", "REVOKED"] = "ACTIVE"
    public_key_pem: Annotated[str, Field(min_length=100, max_length=2048)]
    not_before: Timestamp
    not_after: Timestamp

    @model_validator(mode="after")
    def validate_window(self) -> "PublicKeyRecord":
        if self.not_after <= self.not_before:
            raise ValueError("key not_after must be after not_before")
        return self


class KeyRegistryDocument(StrictModel):
    protocol_version: Literal["1.0"] = "1.0"
    keys: list[PublicKeyRecord]


class TaskStoreDocument(StrictModel):
    protocol_version: Literal["1.0"] = "1.0"
    tasks: list[TaskContext]


class IssueCapabilityInput(StrictModel):
    request: AgentRequest
    ttl_seconds: Annotated[int, Field(ge=1, le=300)] = 60


class VerifyCapabilityInput(StrictModel):
    capability: SignedCapability
    request: AgentRequest
    expected_audience: Identifier


class VerifyReceiptInput(StrictModel):
    receipt: SignedReceipt
    expected_broker_id: Identifier


class VerificationResult(StrictModel):
    valid: Literal[True] = True
    code: Literal["OK"] = "OK"


class ExecutionBundle(StrictModel):
    request: AgentRequest
    capability: SignedCapability
    holder_proof: HolderProof


AgentRequest.model_rebuild()
AllowedAction.model_rebuild()
