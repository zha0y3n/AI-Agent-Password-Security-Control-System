from __future__ import annotations

import pytest

from agent_aa.errors import AuthorizationDenied, VerificationError


def test_normal_capability_issue_and_verify(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], ttl_seconds=60, now=env["now"])
    env["cap_verifier"].verify(
        capability,
        env["request"],
        expected_audience="broker-01",
        now=env["now"],
    )
    assert capability.body.task_id == "task-test-001"
    assert capability.body.agent_id == "agent-test-01"
    assert capability.body.service == "git"
    assert capability.body.resource == "repo/course-project"
    assert capability.body.operation == "read_file"
    assert capability.body.audience == "broker-01"
    assert capability.body.credential_epoch == 17
    assert capability.body.ttl_seconds == 60


def test_aa_rejects_agent_selected_wrong_resource(protocol_env) -> None:
    env = protocol_env
    request = env["request"].model_copy(update={"resource": "repo/private"})
    with pytest.raises(AuthorizationDenied) as caught:
        env["authority"].issue_capability(request, now=env["now"])
    assert caught.value.code == "REQUEST_NOT_AUTHORIZED"


def test_aa_rejects_changed_request_body(protocol_env) -> None:
    env = protocol_env
    request = env["request"].model_copy(update={"body": {"admin": True}})
    with pytest.raises(AuthorizationDenied):
        env["authority"].issue_capability(request, now=env["now"])


def test_policy_does_not_confuse_boolean_and_integer_body(protocol_env) -> None:
    env = protocol_env
    action = env["task"].allowed_actions[0].model_copy(update={"body": 1})
    task = env["task"].model_copy(update={"allowed_actions": [action]})
    from agent_aa.authority import AuthorizationAuthority
    from agent_aa.policy import AuthorizationPolicy, TrustedTaskStore

    authority = AuthorizationAuthority(
        issuer_id="aa-test-01",
        issuer_key_id="aa-key-test-01",
        private_key=env["aa_key"],
        policy=AuthorizationPolicy(TrustedTaskStore([task])),
        key_registry=env["registry"],
    )
    request = env["request"].model_copy(update={"body": True})
    with pytest.raises(AuthorizationDenied):
        authority.issue_capability(request, now=env["now"])


def test_aa_rejects_unknown_task_instead_of_trusting_agent_context(protocol_env) -> None:
    env = protocol_env
    request = env["request"].model_copy(update={"task_id": "task-attacker-001"})
    with pytest.raises(AuthorizationDenied) as caught:
        env["authority"].issue_capability(request, now=env["now"])
    assert caught.value.code == "UNKNOWN_TASK"


def test_aa_rejects_excessive_ttl(protocol_env) -> None:
    env = protocol_env
    with pytest.raises(AuthorizationDenied) as caught:
        env["authority"].issue_capability(env["request"], ttl_seconds=61, now=env["now"])
    assert caught.value.code == "TTL_EXCEEDS_POLICY"


def test_tampered_capability_signature_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    tampered_body = capability.body.model_copy(update={"resource": "repo/private"})
    tampered = capability.model_copy(update={"body": tampered_body})
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(tampered, env["request"], expected_audience="broker-01", now=env["now"])
    assert caught.value.code == "INVALID_SIGNATURE"


def test_tampered_credential_epoch_fails_signature(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    tampered_body = capability.body.model_copy(update={"credential_epoch": 18})
    tampered = capability.model_copy(update={"body": tampered_body})
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(tampered, env["request"], expected_audience="broker-01", now=env["now"])
    assert caught.value.code == "INVALID_SIGNATURE"


def test_expired_capability_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], ttl_seconds=10, now=env["now"])
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(
            capability, env["request"], expected_audience="broker-01", now=env["now"] + 10
        )
    assert caught.value.code == "CAPABILITY_EXPIRED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "task-cross-001"),
        ("resource", "repo/other"),
        ("service", "database"),
        ("operation", "create_issue"),
        ("path", "/repos/course-project/files/keys.txt"),
    ],
)
def test_request_binding_mismatch_fails(protocol_env, field: str, value: str) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    changed = env["request"].model_copy(update={field: value})
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(capability, changed, expected_audience="broker-01", now=env["now"])
    assert caught.value.code in {"REQUEST_BINDING_MISMATCH", "REQUEST_HASH_MISMATCH"}


def test_request_hash_mismatch_for_nonduplicated_field(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    changed = env["request"].model_copy(update={"request_id": "req_changed-001"})
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(capability, changed, expected_audience="broker-01", now=env["now"])
    assert caught.value.code == "REQUEST_HASH_MISMATCH"


def test_wrong_audience_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    with pytest.raises(VerificationError) as caught:
        env["cap_verifier"].verify(capability, env["request"], expected_audience="broker-02", now=env["now"])
    assert caught.value.code == "AUDIENCE_MISMATCH"
