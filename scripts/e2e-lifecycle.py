#!/usr/bin/env python3
"""A+B Credential lifecycle end-to-end check.

This script exercises A's BROKER_LIVE resolver against a running B:

  ACTIVE issue -> execute
  rotate between issue and execute -> old Capability rejected
  revoke -> A refuses to issue
  status endpoint unavailable -> A fails closed

It copies the existing A runtime so B's trusted key registry still matches,
then rewrites only the lifecycle/validity fields in the copy.

Prerequisites:
  - B and Mock are running (default 127.0.0.1:8080 / :9090)
  - B has BROKER_ENABLE_RESET=1 for the --reset path
  - .runtime/public-keys.json is the key registry B trusts
  - .env contains BROKER_ADMIN_TOKEN and MOCK_GIT_TOKEN

Usage:
  .venv/bin/python scripts/e2e-lifecycle.py --reset
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_aa.agent import DeterministicAgent
from agent_aa.authority import AuthorizationAuthority
from agent_aa.canonical import canonical_json
from agent_aa.crypto import load_private_key_pem
from agent_aa.errors import AuthorizationDenied
from agent_aa.holder import create_holder_proof
from agent_aa.lifecycle import BrokerCredentialStatusResolver
from agent_aa.models import ExecutionBundle, SignedCapability
from agent_aa.policy import AuthorizationPolicy, TrustedTaskStore
from agent_aa.runtime import load_runtime

PASS = 0
FAIL = 0
ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "credential-broker" / ".env"


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name}" + (f"  ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f"  ({detail})" if detail else ""))


def _read_env(path: Path, key: str) -> str:
    if not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return ""


def http(
    method: str,
    url: str,
    body: bytes | None = None,
    *,
    admin_token: str | None = None,
) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if admin_token:
        headers["Authorization"] = f"Bearer {admin_token}"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode("utf-8", errors="replace")}
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach {url}: {exc.reason}") from exc


def _copy_runtime(source: Path, *, broker_url: str, audience: str) -> Path:
    temp = Path(tempfile.mkdtemp(prefix="a-lifecycle-"))
    runtime = temp / "runtime"
    shutil.copytree(source, runtime)

    now = int(time.time())
    tasks_path = runtime / "trusted-tasks.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
    task = tasks["tasks"][0]
    task["status"] = "ACTIVE"
    task["valid_from"] = now - 60
    task["expires_at"] = now + 3600
    for action in task["allowed_actions"]:
        action["audience"] = audience
    tasks_path.write_text(json.dumps(tasks), encoding="utf-8")

    config_path = runtime / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["credential_status_mode"] = "BROKER_LIVE"
    config["broker_status_endpoints"] = {audience: broker_url}
    config["broker_status_timeout_seconds"] = 2
    config["allow_insecure_broker_status_urls"] = urlsplit(broker_url).scheme == "http"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return runtime


def _status_epoch(broker: str, credential_id: str) -> tuple[int, int | None, str]:
    code, body = http("GET", f"{broker}/v1/credentials/{credential_id}/status")
    epoch = body.get("credential_epoch") if isinstance(body, dict) else None
    state = body.get("status", "") if isinstance(body, dict) else ""
    return code, epoch, state


def _challenge(broker: str, agent_id: str) -> str:
    code, body = http("POST", f"{broker}/v1/challenge", canonical_json({"agent_id": agent_id}))
    if code != 201:
        raise SystemExit(f"Broker refused challenge: HTTP {code} {body}")
    return body["challenge"]


def _execute(
    broker: str,
    request: Any,
    capability: SignedCapability,
    agent_key: Any,
    agent_id: str,
) -> tuple[int, Any]:
    challenge = _challenge(broker, agent_id)
    proof = create_holder_proof(capability, request, challenge, agent_private_key=agent_key)
    bundle = ExecutionBundle(request=request, capability=capability, holder_proof=proof)
    return http("POST", f"{broker}/v1/execute", canonical_json(bundle))


def _mock_calls(mock: str) -> int:
    code, body = http("GET", f"{mock}/stats")
    if code != 200:
        raise SystemExit(f"Mock stats unavailable: HTTP {code}")
    return int(body.get("calls", {}).get("git", 0))


def _seed(broker: str, credential_id: str, secret: str, token: str) -> None:
    code, body = http("POST", f"{broker}/v1/admin/reset", admin_token=token)
    if code == 403 and isinstance(body, dict) and body.get("error", {}).get("code") == "RESET_DISABLED":
        raise SystemExit("BROKER_ENABLE_RESET is not enabled; start B with BROKER_ENABLE_RESET=1")
    if code != 200:
        raise SystemExit(f"Broker reset failed: HTTP {code} {body}")

    code, body = http(
        "POST",
        f"{broker}/v1/credentials",
        canonical_json({"credential_id": credential_id, "provider": "git", "secret": secret}),
        admin_token=token,
    )
    if code != 201:
        raise SystemExit(f"Credential create failed: HTTP {code} {body}")

    for _ in range(16):
        code, body = http(
            "POST",
            f"{broker}/v1/credentials/{credential_id}/rotate",
            canonical_json({"secret": secret}),
            admin_token=token,
        )
        if code != 200:
            raise SystemExit(f"Credential rotate failed: HTTP {code} {body}")


def main() -> None:
    parser = argparse.ArgumentParser(description="A+B Credential lifecycle E2E")
    parser.add_argument("--runtime", type=Path, default=ROOT / ".runtime")
    parser.add_argument("--broker", default="http://127.0.0.1:8080")
    parser.add_argument("--mock", default="http://127.0.0.1:9090")
    parser.add_argument("--audience", default="broker-01")
    parser.add_argument("--credential-id", default="github-prod")
    parser.add_argument("--admin-token", default=os.environ.get("BROKER_ADMIN_TOKEN", ""))
    parser.add_argument("--secret", default=os.environ.get("MOCK_GIT_TOKEN", ""))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset B and seed a fresh Credential (requires BROKER_ENABLE_RESET=1).",
    )
    args = parser.parse_args()

    if not args.runtime.exists():
        raise SystemExit(f"A runtime not found: {args.runtime}; run agent-aa init-demo first")
    token = args.admin_token or _read_env(ENV_FILE, "BROKER_ADMIN_TOKEN")
    secret = args.secret or _read_env(ENV_FILE, "MOCK_GIT_TOKEN")
    if not token:
        raise SystemExit("BROKER_ADMIN_TOKEN is required (env, --admin-token, or credential-broker/.env)")
    if not secret:
        raise SystemExit("MOCK_GIT_TOKEN is required (env, --secret, or credential-broker/.env)")

    runtime = _copy_runtime(args.runtime, broker_url=args.broker, audience=args.audience)
    try:
        authority, registry, task_store, config = load_runtime(runtime)
        task = task_store.get("task-demo-001")
        agent = DeterministicAgent(agent_id=config.agent_id, agent_key_id=config.agent_key_id)
        request = agent.request_for(task)
        agent_key = load_private_key_pem((runtime / "agent-private-key.pem").read_bytes())

        if args.reset:
            print("0. Reset and seed B")
            _seed(args.broker, args.credential_id, secret, token)
            code, epoch, state = _status_epoch(args.broker, args.credential_id)
            check("B seeded to ACTIVE epoch 17", code == 200 and epoch == 17 and state == "ACTIVE", f"{code} {state} {epoch}")

        code, current_epoch, state = _status_epoch(args.broker, args.credential_id)
        if code != 200 or not isinstance(current_epoch, int) or state != "ACTIVE":
            raise SystemExit(
                f"Credential {args.credential_id!r} is not ACTIVE at B: HTTP {code} {state} {current_epoch}; "
                "start B and run with --reset"
            )

        print("1. ACTIVE: AA reads the live epoch and B executes")
        cap = authority.issue_capability(request, ttl_seconds=60)
        check("Capability carries B's current epoch", cap.body.credential_epoch == current_epoch, str(cap.body.credential_epoch))
        before = _mock_calls(args.mock)
        code, out = _execute(args.broker, request, cap, agent_key, config.agent_id)
        allowed = code == 200 and out.get("decision", {}).get("allowed") is True
        check("Broker executes the valid Capability", allowed, f"HTTP {code} {out.get('decision', {}).get('code')}")
        check("Upstream side effect happened exactly once", _mock_calls(args.mock) == before + 1)

        print("2. Rotation between issue and execute rejects the old Capability")
        old_cap = authority.issue_capability(request, ttl_seconds=60)
        check("Old Capability is bound to the pre-rotation epoch", old_cap.body.credential_epoch == current_epoch)
        code, body = http(
            "POST",
            f"{args.broker}/v1/credentials/{args.credential_id}/rotate",
            canonical_json({"secret": secret}),
            admin_token=token,
        )
        rotated_epoch = current_epoch + 1
        check(
            "B rotated to the next epoch",
            code == 200 and body.get("credential_epoch") == rotated_epoch,
            f"HTTP {code} {body.get('credential_epoch')}",
        )
        new_cap = authority.issue_capability(request, ttl_seconds=60)
        check(
            "New Capability follows the rotated epoch",
            new_cap.body.credential_epoch == rotated_epoch,
            str(new_cap.body.credential_epoch),
        )

        before = _mock_calls(args.mock)
        code, out = _execute(args.broker, request, old_cap, agent_key, config.agent_id)
        code_name = out.get("decision", {}).get("code") or out.get("error", {}).get("code")
        check(
            "Old Capability is rejected after rotation",
            code == 403 and code_name == "CREDENTIAL_EPOCH_MISMATCH",
            f"HTTP {code} {code_name}",
        )
        check("No Credential was loaded for the old Capability", out.get("credential_loaded") is not True)
        check("No upstream side effect for the old Capability", _mock_calls(args.mock) == before)

        print("3. Revocation makes AA refuse to issue")
        code, body = http(
            "POST",
            f"{args.broker}/v1/credentials/{args.credential_id}/revoke",
            admin_token=token,
        )
        check("B revoked the Credential", code == 200 and body.get("status") == "REVOKED", f"HTTP {code}")
        try:
            authority.issue_capability(request, ttl_seconds=60)
        except AuthorizationDenied as exc:
            check("AA fails closed after revocation", exc.code == "CREDENTIAL_INACTIVE", exc.code)
        else:
            check("AA fails closed after revocation", False, "issued a Capability")

        print("4. Unavailable status endpoint fails closed")
        unavailable = AuthorizationPolicy(
            TrustedTaskStore([task]),
            credential_status_resolver=BrokerCredentialStatusResolver(
                {args.audience: "http://127.0.0.1:1"},
                timeout_seconds=0.2,
                allow_insecure_http=True,
            ),
        )
        unavailable_authority = AuthorizationAuthority(
            issuer_id=config.issuer_id,
            issuer_key_id=config.issuer_key_id,
            private_key=authority.private_key,
            policy=unavailable,
            key_registry=registry,
        )
        try:
            unavailable_authority.issue_capability(request, ttl_seconds=60)
        except AuthorizationDenied as exc:
            check("AA fails closed when Status is unavailable", exc.code == "CREDENTIAL_STATUS_UNAVAILABLE", exc.code)
        else:
            check("AA fails closed when Status is unavailable", False, "issued a Capability")
    finally:
        shutil.rmtree(runtime.parent, ignore_errors=True)

    print(f"\n{PASS} passed, {FAIL} failed")
    if FAIL:
        raise SystemExit(1)
    print("全部通过。")


if __name__ == "__main__":
    main()
