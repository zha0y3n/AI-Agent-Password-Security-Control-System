"""FastAPI surface for the Authorization Authority."""

from __future__ import annotations

import time
from typing import TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from .authority import AuthorizationAuthority, CapabilityVerifier
from .canonical import strict_json_loads
from .errors import (
    AuthorizationDenied,
    CanonicalizationError,
    ProtocolError,
    RequestTooLarge,
    VerificationError,
)
from .keys import KeyRegistry
from .models import (
    IssueCapabilityInput,
    PublicKeyRecord,
    SignedCapability,
    VerificationResult,
    VerifyCapabilityInput,
    VerifyReceiptInput,
)
from .receipt import ReceiptVerifier

ModelT = TypeVar("ModelT", bound=BaseModel)
MAX_REQUEST_BYTES = 1 << 20


async def _read_limited_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_REQUEST_BYTES:
            raise RequestTooLarge()
    return bytes(body)


async def _strict_body(request: Request, model: type[ModelT]) -> ModelT:
    try:
        data = strict_json_loads(await _read_limited_body(request))
        return model.model_validate(data)
    except RecursionError as exc:
        raise CanonicalizationError("JSON nesting is too deep") from exc


def _error_status(error: ProtocolError) -> int:
    if isinstance(error, RequestTooLarge):
        return 413
    if isinstance(error, AuthorizationDenied):
        return 403
    if isinstance(error, VerificationError):
        return 401
    return 400


def create_app(authority: AuthorizationAuthority, key_registry: KeyRegistry) -> FastAPI:
    app = FastAPI(
        title="Agent Credential Guard - Authorization Authority",
        version="0.1.0",
        description="Strict task-bound SM2 Capability issuance. Holder private keys and business credentials are absent.",
    )

    @app.exception_handler(ProtocolError)
    async def protocol_error_handler(_: Request, exc: ProtocolError) -> JSONResponse:
        return JSONResponse(status_code=_error_status(exc), content={"error": {"code": exc.code, "message": exc.message}})

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "SCHEMA_VALIDATION_FAILED", "message": str(exc)}},
        )

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "component": "authorization-authority",
            "protocol_version": "1.0",
            "server_time": int(time.time()),
        }

    @app.get("/v1/public-keys/{key_id}", response_model=PublicKeyRecord)
    async def public_key(key_id: str) -> PublicKeyRecord:
        return key_registry.find(key_id)

    @app.post("/v1/capabilities/issue", response_model=SignedCapability)
    async def issue(request: Request) -> SignedCapability:
        payload = await _strict_body(request, IssueCapabilityInput)
        return authority.issue_capability(payload.request, ttl_seconds=payload.ttl_seconds)

    @app.post("/v1/capabilities/verify", response_model=VerificationResult)
    async def verify(request: Request) -> VerificationResult:
        payload = await _strict_body(request, VerifyCapabilityInput)
        CapabilityVerifier(key_registry, trusted_issuer=authority.issuer_id).verify(
            payload.capability,
            payload.request,
            expected_audience=payload.expected_audience,
        )
        return VerificationResult()

    @app.post("/v1/receipts/verify", response_model=VerificationResult)
    async def verify_receipt(request: Request) -> VerificationResult:
        payload = await _strict_body(request, VerifyReceiptInput)
        ReceiptVerifier(key_registry).verify(
            payload.receipt,
            expected_broker_id=payload.expected_broker_id,
        )
        return VerificationResult()

    return app
