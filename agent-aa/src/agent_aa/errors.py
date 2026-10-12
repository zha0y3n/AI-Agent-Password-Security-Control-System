"""Fail-closed protocol errors with stable machine-readable codes."""

from __future__ import annotations


class ProtocolError(ValueError):
    """A validation, authorization, or cryptographic verification failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CanonicalizationError(ProtocolError):
    def __init__(self, message: str) -> None:
        super().__init__("CANONICALIZATION_ERROR", message)


class AuthorizationDenied(ProtocolError):
    pass


class VerificationError(ProtocolError):
    pass
