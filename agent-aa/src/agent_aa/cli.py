"""Command-line demos and development server."""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer

from .agent import DeterministicAgent
from .api import create_app
from .canonical import canonical_json
from .crypto import load_private_key_pem
from .demo import build_demo
from .holder import HolderProofVerifier, create_holder_proof, new_challenge
from .runtime import initialize_demo_runtime, load_runtime

app = typer.Typer(no_args_is_help=True, help="Agent + Authorization Authority development commands")


@app.command("demo")
def demo_command() -> None:
    """Run the complete in-memory Agent -> AA -> Capability -> HolderProof loop."""

    bundle, details = build_demo()
    output = {
        "verified": True,
        "challenge": details["challenge"],
        "bundle": bundle.model_dump(mode="json"),
    }
    typer.echo(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))


@app.command("init-demo")
def init_demo_command(
    directory: Path = typer.Option(Path(".runtime"), "--directory", "-d"),
    force: bool = typer.Option(False, help="Overwrite an existing demo runtime."),
) -> None:
    """Generate non-production AA/Agent keys and a fixed trusted task."""

    config = initialize_demo_runtime(directory.resolve(), overwrite=force)
    typer.echo(f"initialized demo runtime: {directory.resolve()}")
    typer.echo(f"issuer={config.issuer_id} agent={config.agent_id}")


@app.command("runtime-demo")
def runtime_demo_command(
    directory: Path = typer.Option(Path(".runtime"), "--directory", "-d"),
) -> None:
    """Use separated on-disk demo identities to emit a Broker-ready bundle."""

    authority, registry, task_store, config = load_runtime(directory.resolve())
    task = task_store.get("task-demo-001")
    request = DeterministicAgent(agent_id=config.agent_id, agent_key_id=config.agent_key_id).request_for(task)
    capability = authority.issue_capability(request, ttl_seconds=60)
    challenge = new_challenge()
    agent_key = load_private_key_pem((directory.resolve() / "agent-private-key.pem").read_bytes())
    proof = create_holder_proof(capability, request, challenge, agent_private_key=agent_key)
    HolderProofVerifier(registry).verify(
        proof,
        capability,
        request,
        expected_challenge=challenge,
        expected_audience=capability.body.audience,
    )
    typer.echo(
        json.dumps(
            {
                "verified": True,
                "challenge": challenge,
                "request": request.model_dump(mode="json"),
                "capability": capability.model_dump(mode="json"),
                "holder_proof": proof.model_dump(mode="json"),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


@app.command("serve")
def serve_command(
    directory: Path = typer.Option(Path(".runtime"), "--directory", "-d"),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000, min=1, max=65535),
) -> None:
    """Start AA from an initialized runtime (never loads the Agent private key)."""

    import uvicorn

    authority, registry, _, _ = load_runtime(directory.resolve())
    uvicorn.run(create_app(authority, registry), host=host, port=port)


def main() -> None:
    app()
