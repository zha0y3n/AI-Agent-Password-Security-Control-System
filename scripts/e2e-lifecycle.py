#!/usr/bin/env python3
"""A+B Credential lifecycle end-to-end check.

This script exercises A's BROKER_LIVE resolver against a running B:

  ACTIVE issue -> execute
  rotate between issue and execute -> old Capability rejected
  forged Status (stale or future epoch, ACTIVE after revoke) -> B rejects at execute
  revoke -> A refuses to issue
  status endpoint unavailable -> A fails closed
  revoke racing execute (with --reset) -> upstream reached only if consume preceded revoke
  audit entries are ZTCANON-JSON-v1 as A encodes them

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
import random
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

from agent_aa.agent import DeterministicAgent
from agent_aa.authority import AuthorizationAuthority
from agent_aa.canonical import canonical_json, strict_json_loads
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


@contextmanager
def _forged_status_server(credential_id: str, epoch: int) -> Iterator[str]:
    """An attacker-controlled Status endpoint that always claims ACTIVE at ``epoch``."""

    payload = canonical_json(
        {
            "credential_id": credential_id,
            "provider": "git",
            "status": "ACTIVE",
            "credential_epoch": epoch,
            "created_at": int(time.time()) - 60,
            "updated_at": int(time.time()),
        }
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _authority_with_status(authority: AuthorizationAuthority, registry: Any, config: Any, task: Any, endpoint: str, audience: str) -> AuthorizationAuthority:
    return AuthorizationAuthority(
        issuer_id=config.issuer_id,
        issuer_key_id=config.issuer_key_id,
        private_key=authority.private_key,
        policy=AuthorizationPolicy(
            TrustedTaskStore([task]),
            credential_status_resolver=BrokerCredentialStatusResolver(
                {audience: endpoint}, timeout_seconds=0.5, allow_insecure_http=True
            ),
        ),
        key_registry=registry,
    )


def _forged_execute(
    args: Any, authority: AuthorizationAuthority, registry: Any, config: Any, task: Any,
    request: Any, agent_key: Any, epoch: int, expected_code: str,
) -> None:  # fmt: skip
    with _forged_status_server(args.credential_id, epoch) as endpoint:
        forged = _authority_with_status(authority, registry, config, task, endpoint, args.audience)
        cap = forged.issue_capability(request, ttl_seconds=60)
    check(f"AA trusts the forged Status and signs epoch {epoch}", cap.body.credential_epoch == epoch)
    before = _mock_calls(args.mock)
    code, out = _execute(args.broker, request, cap, agent_key, config.agent_id)
    code_name = out.get("decision", {}).get("code")
    check(f"B rejects it at execute ({expected_code})", code == 403 and code_name == expected_code, f"HTTP {code} {code_name}")
    check("No Credential loaded and no upstream call", out.get("credential_loaded") is not True and _mock_calls(args.mock) == before)


def _audit_entries(broker: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    start = 1
    while True:
        code, body = http("GET", f"{broker}/v1/audit?from={start}&limit=1000")
        if code != 200:
            raise SystemExit(f"Broker audit export failed: HTTP {code}")
        records = body.get("records") if isinstance(body, dict) else body
        if not records:
            return entries
        entries.extend(records)
        start = records[-1]["seq"] + 1


def _event_seq(entries: list[dict[str, Any]], event: str, **match: str) -> int | None:
    for record in entries:
        entry = json.loads(record["entry"])
        if entry["type"] == event and all(entry["data"].get(k) == v for k, v in match.items()):
            return int(record["seq"])
    return None


def _create_credential(broker: str, credential_id: str, secret: str, token: str) -> None:
    code, body = http("POST", f"{broker}/v1/admin/reset", admin_token=token)
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


def _revocation_race(
    args: Any, authority: AuthorizationAuthority, config: Any, request: Any, agent_key: Any,
    secret: str, token: str,
) -> None:  # fmt: skip
    executed = rejected = 0
    unsafe: list[str] = []
    for round_no in range(1, args.race_rounds + 1):
        _create_credential(args.broker, args.credential_id, secret, token)
        http("POST", f"{args.mock}/reset")
        cap = authority.issue_capability(request, ttl_seconds=60)
        proof = create_holder_proof(cap, request, _challenge(args.broker, config.agent_id), agent_private_key=agent_key)
        bundle = canonical_json(ExecutionBundle(request=request, capability=cap, holder_proof=proof))
        barrier = threading.Barrier(2)
        result: dict[str, Any] = {}

        def execute() -> None:
            barrier.wait()
            result["execute"] = http("POST", f"{args.broker}/v1/execute", bundle)

        def revoke() -> None:
            barrier.wait()
            # Execution verifies two SM2 signatures before its consume transaction; jitter
            # the revoke so both linearization orders actually occur across rounds.
            time.sleep(random.uniform(0, args.race_jitter_ms / 1000))
            result["revoke"] = http(
                "POST", f"{args.broker}/v1/credentials/{args.credential_id}/revoke", admin_token=token
            )

        threads = [threading.Thread(target=execute), threading.Thread(target=revoke)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        code, out = result["execute"]
        revoke_code, _ = result["revoke"]
        calls = _mock_calls(args.mock)
        entries = _audit_entries(args.broker)
        consume_seq = _event_seq(entries, "capability.consume", cap_id=cap.body.capability_id)
        revoke_seq = _event_seq(entries, "credential.revoke", credential_id=args.credential_id)
        allowed = code == 200 and out.get("decision", {}).get("allowed") is True
        detail = f"round {round_no}: HTTP {code} {out.get('decision', {}).get('code')} calls={calls} consume={consume_seq} revoke={revoke_seq}"
        if revoke_code != 200 or revoke_seq is None:
            unsafe.append(f"{detail} (revoke failed: HTTP {revoke_code})")
        elif calls > 0 and not (consume_seq is not None and consume_seq < revoke_seq):
            unsafe.append(f"{detail} (upstream reached although revoke was linearized first)")
        elif calls > 1 or (allowed and calls != 1):
            unsafe.append(f"{detail} (unexpected upstream call count)")
        elif not allowed and out.get("credential_loaded") is True and calls:
            unsafe.append(f"{detail} (credential used on a rejected execution)")
        if allowed:
            executed += 1
        else:
            rejected += 1
    check(
        f"{args.race_rounds} revoke/execute races are linearizable",
        not unsafe,
        f"executed-before-revoke={executed}, rejected={rejected}" + ("; " + " | ".join(unsafe[:3]) if unsafe else ""),
    )


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
    parser.add_argument("--race-jitter-ms", type=float, default=1.0, help="Max random delay before each revoke.")
    parser.add_argument(
        "--race-rounds",
        type=int,
        default=20,
        help="Revocation race rounds; each resets B, so they run only with --reset (0 disables).",
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

        print("3. Forged Status: B's execute-time check is the final authority")
        _forged_execute(
            args, authority, registry, config, task, request, agent_key, rotated_epoch + 5, "CREDENTIAL_EPOCH_MISMATCH"
        )
        _forged_execute(
            args, authority, registry, config, task, request, agent_key, current_epoch, "CREDENTIAL_EPOCH_MISMATCH"
        )

        print("4. Revocation makes AA refuse to issue")
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
        _, revoked_epoch, _ = _status_epoch(args.broker, args.credential_id)
        _forged_execute(
            args, authority, registry, config, task, request, agent_key, revoked_epoch, "CREDENTIAL_INACTIVE"
        )

        print("5. Unavailable status endpoint fails closed")
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

        print("6. Audit chain")
        code, verdict = http("GET", f"{args.broker}/v1/audit/verify")
        check("B's audit chain and checkpoints verify", code == 200 and verdict.get("valid") is True, f"{verdict.get('entries')} entries")
        entries = _audit_entries(args.broker)
        non_canonical = [
            record["seq"]
            for record in entries
            if canonical_json(strict_json_loads(record["entry"].encode())) != record["entry"].encode()
        ]
        check("Every audit entry is ZTCANON-JSON-v1 as A encodes it", entries and not non_canonical, f"{len(entries)} entries")
        if args.reset and args.race_rounds > 0:
            print("7. Revocation racing execution")
            _revocation_race(args, authority, config, request, agent_key, secret, token)

    finally:
        shutil.rmtree(runtime.parent, ignore_errors=True)

    print(f"\n{PASS} passed, {FAIL} failed")
    if FAIL:
        raise SystemExit(1)
    print("全部通过。")


if __name__ == "__main__":
    main()
