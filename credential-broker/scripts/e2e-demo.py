"""A + B HTTP 全链路联调：Agent -> AA -> Capability -> Challenge -> Holder Proof -> Broker -> Vault
-> Mock API -> Receipt -> Audit，并逐条验证攻击样例被拒绝。

用法（AA、Broker、Mock 已启动且已 seed，见 credential-broker/README.md）：
  .venv/bin/python credential-broker/scripts/e2e-demo.py [--runtime .runtime] [--aa URL] [--broker URL] [--mock URL]

本脚本扮演 Agent：只读取 A 运行时中的 Agent 身份、Agent 私钥与任务定义，从不接触业务 Credential。
Capability 由 AA 的 HTTP 接口签发，回执用 A 的 ReceiptVerifier 和 Broker 公布的公钥记录复核。
只依赖标准库与已安装的 agent-aa。任一预期不符时以非零状态退出。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from agent_aa.agent import DeterministicAgent
from agent_aa.authority import capability_hash, request_hash
from agent_aa.canonical import canonical_json, strict_json_loads
from agent_aa.crypto import b64url_encode, generate_sm2_private_key, load_private_key_pem, protocol_message, sign_sm2, sm3_hex
from agent_aa.holder import HOLDER_PROOF_DOMAIN, create_holder_proof
from agent_aa.keys import KeyRegistry
from agent_aa.models import (
    AgentRequest,
    ExecutionBundle,
    HolderProof,
    HolderProofBody,
    KeyRegistryDocument,
    ProtocolSignature,
    SignedCapability,
    SignedReceipt,
)
from agent_aa.policy import TrustedTaskStore
from agent_aa.receipt import ReceiptVerifier

failures: list[str] = []


def http(method: str, url: str, body: bytes | None = None) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


class Agent:
    def __init__(self, runtime: Path, aa: str, broker: str) -> None:
        config = strict_json_loads((runtime / "config.json").read_bytes())
        self.agent_id, self.agent_key_id = config["agent_id"], config["agent_key_id"]
        self.key = load_private_key_pem((runtime / "agent-private-key.pem").read_bytes())
        self.task = TrustedTaskStore.from_path(runtime / "trusted-tasks.json").get("task-demo-001")
        self.aa, self.broker = aa, broker

    def request(self) -> AgentRequest:
        return DeterministicAgent(agent_id=self.agent_id, agent_key_id=self.agent_key_id).request_for(self.task)

    def issue(self, request: AgentRequest) -> tuple[int, Any]:
        body = canonical_json({"request": request.model_dump(mode="json"), "ttl_seconds": 60})
        return http("POST", f"{self.aa}/v1/capabilities/issue", body)

    def challenge(self) -> str:
        code, body = http("POST", f"{self.broker}/v1/challenge", canonical_json({"agent_id": self.agent_id}))
        if code != 201:
            sys.exit(f"broker refused challenge: {code} {body}")
        return body["challenge"]

    def execute(self, request: AgentRequest, cap: SignedCapability, proof: HolderProof) -> tuple[int, Any, bytes]:
        raw = canonical_json(ExecutionBundle(request=request, capability=cap, holder_proof=proof))
        code, body = http("POST", f"{self.broker}/v1/execute", raw)
        return code, body, raw

    def proof(self, cap: SignedCapability, request: AgentRequest) -> HolderProof:
        return create_holder_proof(cap, request, self.challenge(), agent_private_key=self.key)


def forged_proof(key: Any, cap: SignedCapability, request: AgentRequest, challenge: str) -> HolderProof:
    """模拟恶意 Agent：绕过 create_holder_proof 的自检，直接对任意请求签持有证明。"""
    now = int(time.time())
    body = HolderProofBody(
        proof_id=f"proof_{uuid.uuid4().hex}",
        capability_id=cap.body.capability_id,
        capability_hash=capability_hash(cap),
        agent_id=cap.body.agent_id,
        agent_key_id=cap.body.agent_key_id,
        audience=cap.body.audience,
        request_hash=request_hash(request),
        challenge=challenge,
        issued_at=now,
        expires_at=now + 30,
    )
    sig = sign_sm2(key, protocol_message(HOLDER_PROOF_DOMAIN, canonical_json(body)))
    return HolderProof(body=body, signature=ProtocolSignature(key_id=body.agent_key_id, value=b64url_encode(sig)))


def denied(code: int, body: Any, want_code: str, want_status: int = 403) -> tuple[bool, str]:
    got = (body or {}).get("decision", {}).get("code") or (body or {}).get("error", {}).get("code")
    return code == want_status and got == want_code, f"HTTP {code} {got}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runtime", type=Path, default=Path(__file__).resolve().parent / ".." / ".." / ".runtime",
                    help="A 的开发运行时目录（默认为仓库根目录下的 .runtime）")
    ap.add_argument("--aa", default="http://127.0.0.1:8000")
    ap.add_argument("--broker", default="http://127.0.0.1:8080")
    ap.add_argument("--mock", default="http://127.0.0.1:9090")
    args = ap.parse_args()
    agent = Agent(args.runtime, args.aa, args.broker)

    code, registry_doc = http("GET", f"{args.broker}/v1/broker/key-registry")
    if code != 200:
        sys.exit(f"cannot fetch broker key registry: {code}")
    receipts = ReceiptVerifier(KeyRegistry(KeyRegistryDocument.model_validate(registry_doc).keys))
    broker_id = registry_doc["keys"][0]["subject_id"]
    _, before = http("GET", f"{args.mock}/stats")

    print("1. 正常执行：Agent -> AA -> Broker -> Mock Git")
    request = agent.request()
    code, cap_body = agent.issue(request)
    if code != 200:
        sys.exit(f"AA refused the demo task: {code} {cap_body}")
    cap = SignedCapability.model_validate(cap_body)
    code, out, raw = agent.execute(request, cap, agent.proof(cap, request))
    check("Broker 执行成功", code == 200 and out["decision"]["allowed"], f"HTTP {code} {out['decision'].get('code')}")
    receipt = SignedReceipt.model_validate(out["receipt"])
    try:
        receipts.verify(receipt, expected_broker_id=broker_id)
        ok = sm3_hex(canonical_json(out["result_envelope"])) == receipt.body.result_hash
        check("A 的 ReceiptVerifier 复核回执，result_hash 与 envelope 一致", ok)
    except Exception as exc:  # noqa: BLE001
        check("A 的 ReceiptVerifier 复核回执", False, repr(exc))
    check("回执 outcome=SUCCESS 且绑定本 Capability", receipt.body.outcome == "SUCCESS"
          and receipt.body.capability_id == cap.body.capability_id, receipt.body.outcome)
    check("结果来自 Mock Git", "course-project" in json.dumps(out["result_envelope"]["upstream_body"]))

    print("2. 攻击样例")
    code, body = http("POST", f"{args.broker}/v1/execute", raw)
    check("原样重放整个 bundle", *denied(code, body, "CHALLENGE_USED"))

    code, again, _ = agent.execute(request, cap, agent.proof(cap, request))
    check("同一 Capability + 新 Challenge：幂等返回同一回执，不再调用上游",
          code == 200 and again["replayed"] and again["receipt"] == out["receipt"], f"HTTP {code}")

    tampered = request.model_copy(update={"path": "/repos/course-project/files/secret.txt"})
    code, body, _ = agent.execute(tampered, cap, forged_proof(agent.key, cap, tampered, agent.challenge()))
    check("篡改请求路径（恶意 Agent 自签持有证明）", *denied(code, body, "REQUEST_HASH_MISMATCH"))

    forged = cap.model_copy(update={"body": cap.body.model_copy(update={"operation": "write_file"})})
    code, body, _ = agent.execute(request, forged, forged_proof(agent.key, forged, request, agent.challenge()))
    check("篡改 Capability（越权为 write_file）", *denied(code, body, "INVALID_SIGNATURE"))

    request2 = agent.request()
    _, cap2_body = agent.issue(request2)
    cap2 = SignedCapability.model_validate(cap2_body)
    thief = generate_sm2_private_key()
    code, body, _ = agent.execute(request2, cap2, forged_proof(thief, cap2, request2, agent.challenge()))
    check("被窃取的 Capability（攻击者私钥签持有证明）", *denied(code, body, "INVALID_SIGNATURE"))
    code, body, _ = agent.execute(request2, cap2, forged_proof(agent.key, cap2, request2, "0" * 64))
    check("伪造 Challenge（非 Broker 签发）", *denied(code, body, "CHALLENGE_UNKNOWN"))

    injected = request.model_copy(update={"resource": "repo/private-repo", "path": "/repos/private-repo/files/secret.txt"})
    code, body = agent.issue(injected)
    check("提示注入：Agent 请求任务外资源，AA 拒绝签发", code != 200, f"HTTP {code} {(body or {}).get('error', {}).get('code')}")

    print("3. 证据")
    _, after = http("GET", f"{args.mock}/stats")
    git_calls = after["calls"].get("git", 0) - before["calls"].get("git", 0)
    check("上游只被调用一次（所有攻击都在 Credential 读取前被拒绝）", git_calls == 1, f"git calls +{git_calls}")
    check("上游没有收到错误 Credential", after["auth_failures"] == before["auth_failures"])
    _, audit = http("GET", f"{args.broker}/v1/audit/verify")
    check("审计哈希链与检查点复核通过", audit.get("valid") is True, f"{audit.get('entries')} entries")

    if failures:
        sys.exit(f"\n{len(failures)} check(s) failed: {failures}")
    print("\n全部通过。")


if __name__ == "__main__":
    main()
