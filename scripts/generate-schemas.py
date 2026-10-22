#!/usr/bin/env python3
"""Export shared JSON Schemas from the authoritative Pydantic models."""

from __future__ import annotations

import json
from pathlib import Path

from agent_aa.models import (
    AgentRequest,
    CredentialStatus,
    ExecutionBundle,
    HolderProof,
    ResultEnvelope,
    SignedCapability,
    SignedReceipt,
    TaskContext,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "shared" / "schemas"
MODELS = {
    "agent-request.schema.json": AgentRequest,
    "credential-status.schema.json": CredentialStatus,
    "task-context.schema.json": TaskContext,
    "signed-capability.schema.json": SignedCapability,
    "holder-proof.schema.json": HolderProof,
    "signed-receipt.schema.json": SignedReceipt,
    "result-envelope.schema.json": ResultEnvelope,
    "execution-bundle.schema.json": ExecutionBundle,
}


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for filename, model in MODELS.items():
        schema = model.model_json_schema(mode="validation")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"https://agent-credential-guard.example/schema/{filename}"
        (OUTPUT / filename).write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(OUTPUT / filename)


if __name__ == "__main__":
    main()
