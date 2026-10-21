"""Development runtime initialization and loading.

Generated keys are never part of the source tree and the runtime directory is
gitignored. Production deployment must replace this file-backed development setup.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from .authority import AuthorizationAuthority
from .canonical import canonical_json, strict_json_loads
from .crypto import generate_sm2_private_key, load_private_key_pem, save_private_key
from .keys import KeyRegistry, make_public_key_record
from .lifecycle import BrokerCredentialStatusResolver
from .models import AllowedAction, StrictModel, TaskContext, TaskStoreDocument
from .policy import AuthorizationPolicy, TrustedTaskStore


class RuntimeConfig(StrictModel):
    protocol_version: str = Field(pattern=r"^1\.0$")
    issuer_id: str
    issuer_key_id: str
    agent_id: str
    agent_key_id: str
    credential_status_mode: Literal["STATIC_DEMO", "BROKER_LIVE"] = "STATIC_DEMO"
    broker_status_endpoints: dict[str, str] = Field(default_factory=dict)
    broker_status_timeout_seconds: int = Field(default=2, ge=1, le=30)
    allow_insecure_broker_status_urls: bool = False


def _write_json(path: Path, value: Any, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, canonical_json(value) + b"\n")
    finally:
        os.close(descriptor)


def initialize_demo_runtime(directory: Path, *, overwrite: bool = False, now: int | None = None) -> RuntimeConfig:
    current = int(time.time()) if now is None else now
    directory.mkdir(parents=True, exist_ok=True)
    config = RuntimeConfig(
        protocol_version="1.0",
        issuer_id="aa-demo-01",
        issuer_key_id="aa-key-demo-01",
        agent_id="agent-demo-01",
        agent_key_id="agent-key-demo-01",
    )
    aa_key = generate_sm2_private_key()
    agent_key = generate_sm2_private_key()
    save_private_key(directory / "aa-private-key.pem", aa_key, overwrite=overwrite)
    save_private_key(directory / "agent-private-key.pem", agent_key, overwrite=overwrite)
    registry = KeyRegistry(
        [
            make_public_key_record(
                key_id=config.issuer_key_id,
                subject_id=config.issuer_id,
                purpose="CAPABILITY_SIGNING",
                public_key=aa_key.public_key(),
                not_before=current - 60,
                not_after=current + 365 * 24 * 3600,
            ),
            make_public_key_record(
                key_id=config.agent_key_id,
                subject_id=config.agent_id,
                purpose="HOLDER_PROOF",
                public_key=agent_key.public_key(),
                not_before=current - 60,
                not_after=current + 365 * 24 * 3600,
            ),
        ]
    )
    task = TaskContext(
        context_id="ctx-demo-001",
        issuer="trusted-task-ui-01",
        task_id="task-demo-001",
        agent_id=config.agent_id,
        agent_key_id=config.agent_key_id,
        status="ACTIVE",
        valid_from=current - 60,
        expires_at=current + 24 * 3600,
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
    _write_json(directory / "config.json", config, overwrite=overwrite)
    _write_json(directory / "public-keys.json", registry.document(), overwrite=overwrite)
    _write_json(directory / "trusted-tasks.json", TaskStoreDocument(tasks=[task]), overwrite=overwrite)
    return config


def load_runtime(directory: Path) -> tuple[AuthorizationAuthority, KeyRegistry, TrustedTaskStore, RuntimeConfig]:
    config = RuntimeConfig.model_validate(strict_json_loads((directory / "config.json").read_bytes()))
    registry = KeyRegistry.from_path(directory / "public-keys.json")
    task_store = TrustedTaskStore.from_path(directory / "trusted-tasks.json")
    aa_key = load_private_key_pem((directory / "aa-private-key.pem").read_bytes())
    status_resolver = None
    if config.credential_status_mode == "BROKER_LIVE":
        required_audiences = {
            action.audience for task in task_store.document().tasks for action in task.allowed_actions
        }
        missing_audiences = required_audiences.difference(config.broker_status_endpoints)
        if missing_audiences:
            raise ValueError("Broker live-status configuration is missing a trusted task audience")
        status_resolver = BrokerCredentialStatusResolver(
            config.broker_status_endpoints,
            timeout_seconds=config.broker_status_timeout_seconds,
            allow_insecure_http=config.allow_insecure_broker_status_urls,
        )
    authority = AuthorizationAuthority(
        issuer_id=config.issuer_id,
        issuer_key_id=config.issuer_key_id,
        private_key=aa_key,
        policy=AuthorizationPolicy(task_store, credential_status_resolver=status_resolver),
        key_registry=registry,
    )
    return authority, registry, task_store, config
