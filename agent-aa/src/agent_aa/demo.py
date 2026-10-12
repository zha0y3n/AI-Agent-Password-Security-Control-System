"""In-memory Agent -> AA -> Capability -> HolderProof closed loop."""

from __future__ import annotations

import time

from .agent import DeterministicAgent
from .authority import AuthorizationAuthority, CapabilityVerifier
from .crypto import generate_sm2_private_key
from .holder import HolderProofVerifier, create_holder_proof, new_challenge
from .keys import KeyRegistry, make_public_key_record
from .models import AllowedAction, ExecutionBundle, TaskContext
from .policy import AuthorizationPolicy, TrustedTaskStore


def build_demo(now: int | None = None) -> tuple[ExecutionBundle, dict[str, object]]:
    current = int(time.time()) if now is None else now
    aa_key = generate_sm2_private_key()
    agent_key = generate_sm2_private_key()
    issuer_id = "aa-demo-01"
    issuer_key_id = "aa-key-demo-01"
    agent_id = "agent-demo-01"
    agent_key_id = "agent-key-demo-01"
    task = TaskContext(
        context_id="ctx-demo-001",
        issuer="trusted-task-ui-01",
        task_id="task-demo-001",
        agent_id=agent_id,
        agent_key_id=agent_key_id,
        status="ACTIVE",
        valid_from=current - 60,
        expires_at=current + 3600,
        allowed_actions=[
            AllowedAction(
                service="git",
                resource="repo/course-project",
                operation="read_file",
                method="GET",
                path="/repos/course-project/files/README.md",
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
                key_id=issuer_key_id,
                subject_id=issuer_id,
                purpose="CAPABILITY_SIGNING",
                public_key=aa_key.public_key(),
                not_before=current - 60,
                not_after=current + 86_400,
            ),
            make_public_key_record(
                key_id=agent_key_id,
                subject_id=agent_id,
                purpose="HOLDER_PROOF",
                public_key=agent_key.public_key(),
                not_before=current - 60,
                not_after=current + 86_400,
            ),
        ]
    )
    authority = AuthorizationAuthority(
        issuer_id=issuer_id,
        issuer_key_id=issuer_key_id,
        private_key=aa_key,
        policy=AuthorizationPolicy(TrustedTaskStore([task])),
        key_registry=registry,
    )
    request = DeterministicAgent(agent_id=agent_id, agent_key_id=agent_key_id).request_for(task)
    capability = authority.issue_capability(request, ttl_seconds=60, now=current)
    challenge = new_challenge()
    proof = create_holder_proof(
        capability,
        request,
        challenge,
        agent_private_key=agent_key,
        now=current,
    )
    CapabilityVerifier(registry, trusted_issuer=issuer_id).verify(
        capability, request, expected_audience="broker-01", now=current
    )
    HolderProofVerifier(registry).verify(
        proof,
        capability,
        request,
        expected_challenge=challenge,
        expected_audience="broker-01",
        now=current,
    )
    return ExecutionBundle(request=request, capability=capability, holder_proof=proof), {
        "registry": registry,
        "task": task,
        "aa_private_key": aa_key,
        "agent_private_key": agent_key,
        "challenge": challenge,
    }
