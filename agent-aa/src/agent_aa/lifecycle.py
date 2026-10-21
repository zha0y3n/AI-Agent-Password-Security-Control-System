"""Fail-closed lookup of Broker-owned Credential lifecycle metadata.

The AA never receives a Credential secret.  It may query only the Broker's
public metadata endpoint to bind a newly issued Capability to the Broker's
current epoch.  The Broker must still repeat this check atomically at execute
time; a lookup here is not a replacement for that linearization point.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import ValidationError

from .canonical import strict_json_loads
from .errors import AuthorizationDenied, CanonicalizationError
from .models import CredentialStatus

MAX_STATUS_RESPONSE_BYTES = 16 * 1024
StatusFetch = Callable[[str, float], tuple[int, bytes]]


class CredentialStatusResolver(Protocol):
    """A trusted source of current Broker lifecycle metadata."""

    def resolve(self, *, credential_id: str, audience: str) -> CredentialStatus: ...


class _NoRedirect(HTTPRedirectHandler):
    """Do not let a Broker response redirect the AA to another authority."""

    def redirect_request(self, *args: object, **kwargs: object) -> Request | None:
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirect())


def _https_fetch(url: str, timeout_seconds: float) -> tuple[int, bytes]:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=timeout_seconds) as response:
            return int(response.status), response.read(MAX_STATUS_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        # An HTTP error is still a failed closed lifecycle lookup.  Its response
        # body is intentionally not parsed or exposed to an Agent.
        return int(exc.code), b""


class BrokerCredentialStatusResolver:
    """Resolve current Credential metadata from a configured Broker audience.

    ``endpoints`` is AA-controlled deployment configuration, not Agent input.
    HTTPS is mandatory by default.  A development-only HTTP opt-in exists for
    the local Docker/loopback demo and must never be enabled in production.
    """

    def __init__(
        self,
        endpoints: Mapping[str, str],
        *,
        timeout_seconds: float = 2.0,
        allow_insecure_http: bool = False,
        fetch: StatusFetch = _https_fetch,
    ) -> None:
        if not 0 < timeout_seconds <= 30:
            raise ValueError("Broker status timeout must be between 0 and 30 seconds")
        self._endpoints = {
            audience: self._validate_endpoint(url, allow_insecure_http=allow_insecure_http)
            for audience, url in endpoints.items()
        }
        self._timeout_seconds = timeout_seconds
        self._fetch = fetch

    @staticmethod
    def _validate_endpoint(url: str, *, allow_insecure_http: bool) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("Broker status endpoint must be an absolute HTTPS URL")
        if parsed.scheme == "http" and not allow_insecure_http:
            raise ValueError("HTTP Broker status endpoint requires explicit development opt-in")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Broker status endpoint must not contain userinfo")
        if parsed.query or parsed.fragment:
            raise ValueError("Broker status endpoint must not contain a query or fragment")
        path = parsed.path.rstrip("/")
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    def resolve(self, *, credential_id: str, audience: str) -> CredentialStatus:
        endpoint = self._endpoints.get(audience)
        if endpoint is None:
            raise AuthorizationDenied(
                "CREDENTIAL_STATUS_UNAVAILABLE",
                "no trusted Broker lifecycle endpoint is configured for the audience",
            )
        url = f"{endpoint}/v1/credentials/{quote(credential_id, safe='')}/status"
        try:
            http_status, raw = self._fetch(url, self._timeout_seconds)
        except (OSError, TimeoutError, URLError, ValueError) as exc:
            raise AuthorizationDenied(
                "CREDENTIAL_STATUS_UNAVAILABLE",
                "Broker lifecycle status could not be obtained",
            ) from exc
        if not isinstance(http_status, int) or not isinstance(raw, bytes) or http_status != 200:
            raise AuthorizationDenied(
                "CREDENTIAL_STATUS_UNAVAILABLE",
                "Broker lifecycle status could not be obtained",
            )
        if len(raw) > MAX_STATUS_RESPONSE_BYTES:
            raise AuthorizationDenied("CREDENTIAL_STATUS_INVALID", "Broker lifecycle status response is too large")
        try:
            status = CredentialStatus.model_validate(strict_json_loads(raw))
        except (CanonicalizationError, ValidationError, RecursionError) as exc:
            raise AuthorizationDenied(
                "CREDENTIAL_STATUS_INVALID",
                "Broker lifecycle status response is invalid",
            ) from exc
        if status.credential_id != credential_id:
            raise AuthorizationDenied(
                "CREDENTIAL_STATUS_MISMATCH",
                "Broker lifecycle status refers to another credential",
            )
        if status.status != "ACTIVE":
            raise AuthorizationDenied("CREDENTIAL_INACTIVE", "credential is not active")
        return status
