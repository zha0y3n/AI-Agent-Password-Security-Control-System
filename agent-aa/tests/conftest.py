from __future__ import annotations

import pytest

from agent_aa.agent import DeterministicAgent
from agent_aa.authority import AuthorizationAuthority, CapabilityVerifier
from agent_aa.crypto import generate_sm2_private_key
from agent_aa.holder import HolderProofVerifier
from agent_aa.keys import KeyRegistry, make_public_key_record
from agent_aa.models import AllowedAction, TaskContext
from agent_aa.policy import AuthorizationPolicy, TrustedTaskStore


@pytest.fixture()
def protocol_env():
    now = 2_000_000_000
    aa_key = generate_sm2_private_key()
    agent_key = generate_sm2_private_key()
    other_agent_key = generate_sm2_private_key()
    broker_key = generate_sm2_private_key()
    task = TaskContext(
        context_id="ctx-test-001",
        issuer="trusted-task-ui-01",
        task_id="task-test-001",
        agent_id="agent-test-01",
        agent_key_id="agent-key-test-01",
        status="ACTIVE",
        valid_from=now - 100,
        expires_at=now + 3600,
        allowed_actions=[
            AllowedAction(
                service="git",
                resource="repo/course-project",
                operation="read_file",
                method="GET",
                path="/repos/course-project/files/README.md",
                query={},
                body=None,
                credential_id="github-prod",
                credential_epoch=17,
                audience="broker-01",
                max_ttl_seconds=60,
            )
        ],
    )
    registry = KeyRegistry(
        [
            make_public_key_record(
                key_id="aa-key-test-01",
                subject_id="aa-test-01",
                purpose="CAPABILITY_SIGNING",
                public_key=aa_key.public_key(),
                not_before=now - 100,
                not_after=now + 7200,
            ),
            make_public_key_record(
                key_id="agent-key-test-01",
                subject_id="agent-test-01",
                purpose="HOLDER_PROOF",
                public_key=agent_key.public_key(),
                not_before=now - 100,
                not_after=now + 7200,
            ),
            make_public_key_record(
                key_id="agent-key-other-01",
                subject_id="agent-other-01",
                purpose="HOLDER_PROOF",
                public_key=other_agent_key.public_key(),
                not_before=now - 100,
                not_after=now + 7200,
            ),
            make_public_key_record(
                key_id="broker-key-test-01",
                subject_id="broker-01",
                purpose="RECEIPT_SIGNING",
                public_key=broker_key.public_key(),
                not_before=now - 100,
                not_after=now + 7200,
            ),
        ]
    )
    store = TrustedTaskStore([task])
    authority = AuthorizationAuthority(
        issuer_id="aa-test-01",
        issuer_key_id="aa-key-test-01",
        private_key=aa_key,
        policy=AuthorizationPolicy(store),
        key_registry=registry,
        clock=lambda: now,
    )
    request = DeterministicAgent(agent_id="agent-test-01", agent_key_id="agent-key-test-01").request_for(task)
    return {
        "now": now,
        "aa_key": aa_key,
        "agent_key": agent_key,
        "other_agent_key": other_agent_key,
        "broker_key": broker_key,
        "task": task,
        "store": store,
        "registry": registry,
        "authority": authority,
        "request": request,
        "cap_verifier": CapabilityVerifier(registry, trusted_issuer="aa-test-01"),
        "proof_verifier": HolderProofVerifier(registry),
    }
