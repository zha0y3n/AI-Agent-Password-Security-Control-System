from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from agent_aa.errors import AuthorizationDenied
from agent_aa.lifecycle import MAX_STATUS_RESPONSE_BYTES, BrokerCredentialStatusResolver


def _status(
    *,
    credential_id: str = "github-prod",
    state: str = "ACTIVE",
    epoch: int = 18,
    extra: dict[str, object] | None = None,
) -> bytes:
    payload: dict[str, object] = {
        "credential_id": credential_id,
        "provider": "git",
        "status": state,
        "credential_epoch": epoch,
        "created_at": 1_999_999_000,
        "updated_at": 2_000_000_000,
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, separators=(",", ":")).encode()


@contextmanager
def _status_server(
    *,
    code: int = 200,
    body: bytes = b"",
    redirect: bool = False,
    sleep_seconds: float = 0.0,
) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if sleep_seconds:
                time.sleep(sleep_seconds)
            if redirect:
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()
                return
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                # The resolver intentionally times out in one test.
                return

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _raw_http_server(response: bytes) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            conn.recv(4096)
            conn.sendall(response)
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        listener.close()
        thread.join(timeout=2)


def _resolver(endpoint: str, *, timeout_seconds: float = 1.0) -> BrokerCredentialStatusResolver:
    return BrokerCredentialStatusResolver(
        {"broker-01": endpoint},
        timeout_seconds=timeout_seconds,
        allow_insecure_http=True,
    )


def test_real_http_status_response_is_accepted() -> None:
    with _status_server(body=_status(epoch=18)) as endpoint:
        status = _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert status.credential_epoch == 18
    assert status.status == "ACTIVE"


def test_redirect_is_unavailable() -> None:
    with _status_server(redirect=True) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_oversized_response_is_invalid() -> None:
    body = b"{" + b" " * (MAX_STATUS_RESPONSE_BYTES + 1) + b"}"
    with _status_server(body=body) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_INVALID"


def test_malformed_json_is_invalid() -> None:
    with _status_server(body=b'{"credential_id":') as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_INVALID"


def test_unknown_field_is_invalid() -> None:
    with _status_server(body=_status(extra={"admin_token": "secret"})) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_INVALID"


def test_non_200_is_unavailable() -> None:
    with _status_server(code=503, body=b"{}") as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_credential_mismatch_is_rejected() -> None:
    with _status_server(body=_status(credential_id="other-prod")) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_MISMATCH"


def test_non_active_credential_is_rejected() -> None:
    with _status_server(body=_status(state="REVOKED")) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_INACTIVE"


def test_timeout_is_unavailable() -> None:
    with _status_server(body=_status(), sleep_seconds=0.5) as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint, timeout_seconds=0.1).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_bad_http_status_line_fails_closed() -> None:
    with _raw_http_server(b"BAD\r\n\r\n") as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_incomplete_http_response_fails_closed() -> None:
    # A truncated 200 body is treated as an invalid payload rather than a
    # transport failure; either way it must not be accepted.
    with _raw_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{") as endpoint:
        with pytest.raises(AuthorizationDenied) as caught:
            _resolver(endpoint).resolve(credential_id="github-prod", audience="broker-01")
    assert caught.value.code in {"CREDENTIAL_STATUS_UNAVAILABLE", "CREDENTIAL_STATUS_INVALID"}


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@broker.example",
        "https://broker.example/?next=1",
        "https://broker.example/#fragment",
    ],
)
def test_unsafe_endpoint_forms_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        BrokerCredentialStatusResolver({"broker-01": url})
