"""Fail-closed lookup of Broker-owned Credential lifecycle metadata.

The AA never receives a Credential secret.  It may query only the Broker's
public metadata endpoint to bind a newly issued Capability to the Broker's
current epoch.  The Broker must still repeat this check atomically at execute
time; a lookup here is not a replacement for that linearization point.
"""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable, Mapping
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, OpenerDirector, Request, build_opener

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


def make_status_ssl_context(
    *,
    ca_file: str | None = None,
    client_cert_file: str | None = None,
    client_key_file: str | None = None,
) -> ssl.SSLContext:
    """Build the TLS context for Broker status lookups.

    ``ca_file`` replaces the system trust store with a deployment CA.  The client
    certificate and key are presented when the Broker requires mTLS; they must be
    configured together.  Any file that cannot be loaded raises at startup.
    """

    if (client_cert_file is None) != (client_key_file is None):
        raise ValueError("Broker status client certificate and key must be configured together")
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert_file is not None:
        context.load_cert_chain(certfile=client_cert_file, keyfile=client_key_file)
    return context


def _make_fetch(opener: OpenerDirector) -> StatusFetch:
    def fetch(url: str, timeout_seconds: float) -> tuple[int, bytes]:
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                return int(response.status), response.read(MAX_STATUS_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            # An HTTP error is still a failed closed lifecycle lookup.  Its response
            # body is intentionally not parsed or exposed to an Agent.
            return int(exc.code), b""

    return fetch


_https_fetch = _make_fetch(build_opener(_NoRedirect()))


class BrokerCredentialStatusResolver:
    """Resolve current Credential metadata from a configured Broker audience.

    ``endpoints`` is AA-controlled deployment configuration, not Agent input.
    HTTPS is mandatory by default.  A development-only HTTP opt-in exists for
    the local Docker/loopback demo and must never be enabled in production.
    ``ssl_context`` (see ``make_status_ssl_context``) supplies a deployment CA
    and, for Brokers that require mTLS, the AA's client certificate.
    """

    def __init__(
        self,
        endpoints: Mapping[str, str],
        *,
        timeout_seconds: float = 2.0,
        allow_insecure_http: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        fetch: StatusFetch | None = None,
    ) -> None:
        if not 0 < timeout_seconds <= 30:
            raise ValueError("Broker status timeout must be between 0 and 30 seconds")
        self._endpoints = {
            audience: self._validate_endpoint(url, allow_insecure_http=allow_insecure_http)
            for audience, url in endpoints.items()
        }
        if ssl_context is not None and any(urlsplit(url).scheme != "https" for url in self._endpoints.values()):
            # A TLS context on a plain HTTP endpoint would silently drop server
            # authentication and the client certificate.
            raise ValueError("Broker status TLS settings require HTTPS endpoints")
        if fetch is None:
            fetch = (
                _https_fetch
                if ssl_context is None
                else _make_fetch(build_opener(_NoRedirect(), HTTPSHandler(context=ssl_context)))
            )
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
        except (OSError, TimeoutError, URLError, ValueError, http.client.HTTPException) as exc:
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
