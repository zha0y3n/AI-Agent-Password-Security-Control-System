from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest

from agent_aa.errors import AuthorizationDenied
from agent_aa.lifecycle import BrokerCredentialStatusResolver, make_status_ssl_context
from agent_aa.runtime import initialize_demo_runtime, load_runtime

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI is required to mint test certificates")

STATUS = json.dumps(
    {
        "credential_id": "github-prod",
        "provider": "git",
        "status": "ACTIVE",
        "credential_epoch": 18,
        "created_at": 1_999_999_000,
        "updated_at": 2_000_000_000,
    },
    separators=(",", ":"),
).encode()


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _ca(directory: Path, name: str) -> None:
    _openssl(
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", str(directory / f"{name}.key"), "-out", str(directory / f"{name}.pem"),
        "-days", "1", "-subj", f"/CN={name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )  # fmt: skip


def _leaf(directory: Path, name: str, ca: str, usage: str) -> None:
    _openssl(
        "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", str(directory / f"{name}.key"), "-out", str(directory / f"{name}.csr"), "-subj", f"/CN={name}",
    )  # fmt: skip
    extensions = directory / f"{name}.ext"
    extensions.write_text(
        "subjectAltName=IP:127.0.0.1\n"
        f"extendedKeyUsage={usage}\n"
        "keyUsage=critical,digitalSignature\n"
        "authorityKeyIdentifier=keyid\n"
        "subjectKeyIdentifier=hash\n",
        encoding="utf-8",
    )
    _openssl(
        "x509", "-req", "-in", str(directory / f"{name}.csr"),
        "-CA", str(directory / f"{ca}.pem"), "-CAkey", str(directory / f"{ca}.key"), "-CAcreateserial",
        "-out", str(directory / f"{name}.pem"), "-days", "1", "-extfile", str(extensions),
    )  # fmt: skip


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("pki")
    _ca(directory, "ca")
    _ca(directory, "rogue-ca")
    _leaf(directory, "broker", "ca", "serverAuth")
    _leaf(directory, "aa", "ca", "clientAuth")
    _leaf(directory, "rogue", "rogue-ca", "clientAuth")
    return directory


@contextmanager
def _mtls_server(pki: Path) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(STATUS)))
            self.end_headers()
            self.wfile.write(STATUS)

        def log_message(self, *args: object) -> None:
            return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki / "broker.pem", pki / "broker.key")
    context.load_verify_locations(pki / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    # A failed client handshake must not leave the server thread blocked.
    server.handle_error = lambda *args: None  # type: ignore[method-assign]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _resolve(endpoint: str, context: ssl.SSLContext) -> str:
    resolver = BrokerCredentialStatusResolver({"broker-01": endpoint}, timeout_seconds=2, ssl_context=context)
    try:
        return str(resolver.resolve(credential_id="github-prod", audience="broker-01").credential_epoch)
    except AuthorizationDenied as exc:
        return exc.code


def test_mtls_with_trusted_client_certificate(pki: Path) -> None:
    context = make_status_ssl_context(
        ca_file=str(pki / "ca.pem"),
        client_cert_file=str(pki / "aa.pem"),
        client_key_file=str(pki / "aa.key"),
    )
    with _mtls_server(pki) as endpoint:
        assert _resolve(endpoint, context) == "18"


def test_mtls_without_client_certificate_fails_closed(pki: Path) -> None:
    with _mtls_server(pki) as endpoint:
        assert _resolve(endpoint, make_status_ssl_context(ca_file=str(pki / "ca.pem"))) == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_mtls_with_untrusted_client_certificate_fails_closed(pki: Path) -> None:
    context = make_status_ssl_context(
        ca_file=str(pki / "ca.pem"),
        client_cert_file=str(pki / "rogue.pem"),
        client_key_file=str(pki / "rogue.key"),
    )
    with _mtls_server(pki) as endpoint:
        assert _resolve(endpoint, context) == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_untrusted_server_certificate_fails_closed(pki: Path) -> None:
    context = make_status_ssl_context(
        ca_file=str(pki / "rogue-ca.pem"),
        client_cert_file=str(pki / "aa.pem"),
        client_key_file=str(pki / "aa.key"),
    )
    with _mtls_server(pki) as endpoint:
        assert _resolve(endpoint, context) == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_client_certificate_requires_key(pki: Path) -> None:
    with pytest.raises(ValueError):
        make_status_ssl_context(client_cert_file=str(pki / "aa.pem"))


def test_unloadable_tls_files_fail_at_startup(pki: Path) -> None:
    with pytest.raises(OSError):
        make_status_ssl_context(ca_file=str(pki / "missing.pem"))
    with pytest.raises(ssl.SSLError):
        make_status_ssl_context(client_cert_file=str(pki / "aa.pem"), client_key_file=str(pki / "broker.key"))


def test_tls_settings_reject_plain_http_endpoints(pki: Path) -> None:
    context = make_status_ssl_context(ca_file=str(pki / "ca.pem"))
    with pytest.raises(ValueError):
        BrokerCredentialStatusResolver(
            {"broker-01": "http://127.0.0.1:8080"}, allow_insecure_http=True, ssl_context=context
        )


def test_runtime_loads_mtls_settings_relative_to_runtime(pki: Path, tmp_path: Path) -> None:
    initialize_demo_runtime(tmp_path)
    for name in ("ca.pem", "aa.pem", "aa.key"):
        shutil.copy(pki / name, tmp_path / name)
    config_path = tmp_path / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    with _mtls_server(pki) as endpoint:
        config.update(
            credential_status_mode="BROKER_LIVE",
            broker_status_endpoints={"broker-01": endpoint},
            broker_status_ca_file="ca.pem",
            broker_status_client_cert_file="aa.pem",
            broker_status_client_key_file="aa.key",
        )
        config_path.write_text(json.dumps(config), encoding="utf-8")
        authority, *_ = load_runtime(tmp_path)
        resolver = authority.policy.credential_status_resolver
        assert resolver is not None
        assert resolver.resolve(credential_id="github-prod", audience="broker-01").credential_epoch == 18

    config["broker_status_client_key_file"] = None
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError):
        load_runtime(tmp_path)
