"""用 A 的真实代码生成一份 Execution Bundle，供 Broker 跨语言联调测试使用。

用法：.venv/bin/python credential-broker/scripts/gen-a-bundle.py <空目录>

在目录中写入 A 的开发运行时（含随机生成的测试私钥，切勿提交）以及：
  bundle.json   Agent 发给 Broker 的 Execution Bundle（AA 签发 + Agent 持有证明）
  interop.json  Broker 侧测试需要的 challenge / issuer / agent 标识
Challenge 由本脚本随机生成，测试会把它预置进 Broker 的 Challenge 存储。
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from agent_aa.agent import DeterministicAgent
from agent_aa.canonical import canonical_json
from agent_aa.crypto import load_private_key_pem
from agent_aa.holder import create_holder_proof
from agent_aa.models import ExecutionBundle
from agent_aa.runtime import initialize_demo_runtime, load_runtime


def main(out: Path) -> None:
    initialize_demo_runtime(out)
    authority, _, task_store, config = load_runtime(out)
    task = task_store.get("task-demo-001")
    request = DeterministicAgent(agent_id=config.agent_id, agent_key_id=config.agent_key_id).request_for(task)
    capability = authority.issue_capability(request, ttl_seconds=60)
    challenge = secrets.token_hex(32)
    agent_key = load_private_key_pem((out / "agent-private-key.pem").read_bytes())
    proof = create_holder_proof(capability, request, challenge, agent_private_key=agent_key)
    bundle = ExecutionBundle(request=request, capability=capability, holder_proof=proof)
    (out / "bundle.json").write_bytes(canonical_json(bundle))
    (out / "interop.json").write_bytes(
        canonical_json({"challenge": challenge, "issuer_id": config.issuer_id, "agent_id": config.agent_id})
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen-a-bundle.py <empty-directory>")
    main(Path(sys.argv[1]))
