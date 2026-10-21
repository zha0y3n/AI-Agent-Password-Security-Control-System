from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from agent_aa.api import create_app
from agent_aa.authority import AuthorizationAuthority
from agent_aa.errors import AuthorizationDenied
from agent_aa.lifecycle import BrokerCredentialStatusResolver
from agent_aa.policy import AuthorizationPolicy, TrustedTaskStore
from agent_aa.runtime import initialize_demo_runtime, load_runtime


def _status(*, credential_id: str = "github-prod", state: str = "ACTIVE", epoch: int = 18) -> bytes:
    return json.dumps(
        {
            "credential_id": credential_id,
            "provider": "git",
            "status": state,
            "credential_epoch": epoch,
            "created_at": 1_999_999_000,
            "updated_at": 2_000_000_000,
        },
        separators=(",", ":"),
    ).encode()


def _resolver(fetch):
    return BrokerCredentialStatusResolver(
        {"broker-01": "https://broker.example"},
        fetch=fetch,
    )


def _authority(env, policy: AuthorizationPolicy) -> AuthorizationAuthority:
    return AuthorizationAuthority(
        issuer_id="aa-test-01",
        issuer_key_id="aa-key-test-01",
        private_key=env["aa_key"],
        policy=policy,
        key_registry=env["registry"],
        clock=lambda: env["now"],
    )


def test_live_broker_epoch_is_bound_into_capability(protocol_env) -> None:
    observed: list[str] = []

    def fetch(url: str, timeout: float) -> tuple[int, bytes]:
        observed.append(url)
        assert timeout == 2.0
        return 200, _status(epoch=18)

    env = protocol_env
    authority = _authority(
        env,
        AuthorizationPolicy(
            TrustedTaskStore([env["task"]]),
            credential_status_resolver=_resolver(fetch),
        ),
    )

    capability = authority.issue_capability(env["request"], now=env["now"])

    assert capability.body.credential_epoch == 18
    assert observed == ["https://broker.example/v1/credentials/github-prod/status"]


def test_inactive_credential_fails_closed_before_issue(protocol_env) -> None:
    env = protocol_env
    policy = AuthorizationPolicy(
        TrustedTaskStore([env["task"]]),
        credential_status_resolver=_resolver(lambda _url, _timeout: (200, _status(state="REVOKED"))),
    )
    authority = _authority(env, policy)

    with pytest.raises(AuthorizationDenied) as caught:
        authority.issue_capability(env["request"], now=env["now"])
    assert caught.value.code == "CREDENTIAL_INACTIVE"


@pytest.mark.parametrize(
    ("response", "code"),
    [
        ((503, b"{}"), "CREDENTIAL_STATUS_UNAVAILABLE"),
        ((200, b'{"credential_id":"github-prod"}'), "CREDENTIAL_STATUS_INVALID"),
        ((200, _status(credential_id="other-prod")), "CREDENTIAL_STATUS_MISMATCH"),
    ],
)
def test_bad_broker_status_fails_closed(protocol_env, response, code: str) -> None:
    env = protocol_env
    policy = AuthorizationPolicy(
        TrustedTaskStore([env["task"]]),
        credential_status_resolver=_resolver(lambda _url, _timeout: response),
    )
    authority = _authority(env, policy)

    with pytest.raises(AuthorizationDenied) as caught:
        authority.issue_capability(env["request"], now=env["now"])
    assert caught.value.code == code


def test_request_must_match_trusted_action_before_status_lookup(protocol_env) -> None:
    env = protocol_env
    calls = 0

    def fetch(_url: str, _timeout: float) -> tuple[int, bytes]:
        nonlocal calls
        calls += 1
        return 200, _status()

    policy = AuthorizationPolicy(
        TrustedTaskStore([env["task"]]),
        credential_status_resolver=_resolver(fetch),
    )
    authority = _authority(env, policy)

    with pytest.raises(AuthorizationDenied) as caught:
        authority.issue_capability(
            env["request"].model_copy(update={"credential_id": "other-prod"}),
            now=env["now"],
        )
    assert caught.value.code == "REQUEST_NOT_AUTHORIZED"
    assert calls == 0


def test_http_status_endpoint_requires_explicit_development_opt_in() -> None:
    with pytest.raises(ValueError, match="explicit development opt-in"):
        BrokerCredentialStatusResolver({"broker-01": "http://127.0.0.1:8080"})

    resolver = BrokerCredentialStatusResolver(
        {"broker-01": "http://127.0.0.1:8080"},
        allow_insecure_http=True,
        fetch=lambda _url, _timeout: (200, _status()),
    )
    assert resolver.resolve(credential_id="github-prod", audience="broker-01").credential_epoch == 18


def test_issue_api_returns_explicit_error_when_broker_status_is_unavailable(protocol_env) -> None:
    env = protocol_env
    authority = _authority(
        env,
        AuthorizationPolicy(
            TrustedTaskStore([env["task"]]),
            credential_status_resolver=_resolver(lambda _url, _timeout: (503, b"{}")),
        ),
    )
    client = TestClient(create_app(authority, env["registry"]))

    response = client.post(
        "/v1/capabilities/issue",
        json={"request": env["request"].model_dump(mode="json"), "ttl_seconds": 60},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CREDENTIAL_STATUS_UNAVAILABLE"


def test_live_runtime_refuses_to_start_without_an_endpoint_for_each_trusted_audience(tmp_path) -> None:
    initialize_demo_runtime(tmp_path, now=2_000_000_000)
    config_path = tmp_path / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["credential_status_mode"] = "BROKER_LIVE"
    config["broker_status_endpoints"] = {}
    config_path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="missing a trusted task audience"):
        load_runtime(tmp_path)
