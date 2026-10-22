#!/usr/bin/env python3
"""Export result_envelope vectors: Broker inputs -> envelope -> canonical bytes -> SM3."""

from __future__ import annotations

import json
from pathlib import Path

from agent_aa.canonical import canonical_json, strict_json_loads
from agent_aa.crypto import sm3_hex
from agent_aa.errors import CanonicalizationError
from agent_aa.models import ResultEnvelope

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "shared" / "test-vectors" / "result-envelope-v1.json"
CAPABILITY_ID = "cap_7f3c2a91d4e8b6051a2c3d4e5f607182"
REQUEST_HASH = "9b1c6e0f4a5d3e2b7c8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c"

CASES = [
    ("success", "SUCCESS", None, 200, '{"repo":"course-project","path":"README.md","content":"hello"}'),
    ("upstream_rejected", "ERROR", "UPSTREAM_REJECTED", 404, '{"error":"not found"}'),
    ("non_canonical_upstream_body", "ERROR", "UPSTREAM_ERROR", 502, '{"latency":1.5}'),
    ("upstream_unreachable", "ERROR", "UPSTREAM_ERROR", None, None),
    ("denied", "DENIED", "CHALLENGE_USED", None, None),
]


def upstream_value(raw: str | None) -> object:
    """Mirror the Broker: canonical JSON stays structured, anything else becomes its text."""

    if raw is None:
        return None
    try:
        return strict_json_loads(raw.encode())
    except CanonicalizationError:
        return raw


def main() -> None:
    vectors = []
    for name, outcome, code, status, raw in CASES:
        envelope = ResultEnvelope(
            capability_id=CAPABILITY_ID,
            request_hash=REQUEST_HASH,
            outcome=outcome,
            code=code,
            upstream_status=status,
            upstream_body=upstream_value(raw),
        )
        canonical = canonical_json(envelope)
        vectors.append(
            {
                "name": name,
                "input": {"outcome": outcome, "code": code, "upstream_status": status, "upstream_body_raw": raw},
                "envelope": json.loads(canonical),
                "canonical_hex": canonical.hex(),
                "result_hash": sm3_hex(canonical),
            }
        )
    document = {
        "protocol_version": "1.0",
        "description": "result_hash = lowercase_hex(SM3(ZTCANON-JSON-v1(result_envelope)))",
        "capability_id": CAPABILITY_ID,
        "request_hash": REQUEST_HASH,
        "vectors": vectors,
    }
    OUTPUT.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
