from __future__ import annotations

import pytest

from agent_aa.errors import VerificationError
from agent_aa.holder import create_holder_proof

CHALLENGE = "11" * 16


def test_holder_proof_complete_loop(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    proof = create_holder_proof(
        capability,
        env["request"],
        CHALLENGE,
        agent_private_key=env["agent_key"],
        now=env["now"],
    )
    env["proof_verifier"].verify(
        proof,
        capability,
        env["request"],
        expected_challenge=CHALLENGE,
        expected_audience="broker-01",
        now=env["now"],
    )


def test_wrong_holder_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    stolen_ticket_proof = create_holder_proof(
        capability,
        env["request"],
        CHALLENGE,
        agent_private_key=env["other_agent_key"],
        now=env["now"],
    )
    with pytest.raises(VerificationError) as caught:
        env["proof_verifier"].verify(
            stolen_ticket_proof,
            capability,
            env["request"],
            expected_challenge=CHALLENGE,
            expected_audience="broker-01",
            now=env["now"],
        )
    assert caught.value.code == "INVALID_SIGNATURE"


def test_wrong_or_stale_challenge_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    proof = create_holder_proof(
        capability, env["request"], CHALLENGE, agent_private_key=env["agent_key"], now=env["now"]
    )
    with pytest.raises(VerificationError) as caught:
        env["proof_verifier"].verify(
            proof,
            capability,
            env["request"],
            expected_challenge="22" * 16,
            expected_audience="broker-01",
            now=env["now"],
        )
    assert caught.value.code == "CHALLENGE_MISMATCH"


def test_expired_holder_proof_fails(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    proof = create_holder_proof(
        capability,
        env["request"],
        CHALLENGE,
        agent_private_key=env["agent_key"],
        now=env["now"],
        lifetime_seconds=10,
    )
    with pytest.raises(VerificationError) as caught:
        env["proof_verifier"].verify(
            proof,
            capability,
            env["request"],
            expected_challenge=CHALLENGE,
            expected_audience="broker-01",
            now=env["now"] + 10,
        )
    assert caught.value.code == "PROOF_EXPIRED"


def test_holder_refuses_request_hash_mismatch(protocol_env) -> None:
    env = protocol_env
    capability = env["authority"].issue_capability(env["request"], now=env["now"])
    modified = env["request"].model_copy(update={"request_id": "req_modified-001"})
    with pytest.raises(VerificationError) as caught:
        create_holder_proof(
            capability, modified, CHALLENGE, agent_private_key=env["agent_key"], now=env["now"]
        )
    assert caught.value.code == "REQUEST_HASH_MISMATCH"
