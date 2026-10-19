"""提示注入越权测试"""
import csv
import json
import time
import requests
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../credential-broker/scripts")))
from pathlib import Path
from datetime import datetime
from e2e_demo_lib import Agent, http, SignedCapability, forged_proof

BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"

BASE_BROKER = "http://127.0.0.1:8080"
BASE_MOCK = "http://127.0.0.1:9090"
RUNTIME_DIR = BROKER_DIR.parent / ".runtime"

def main():
    agent = Agent(RUNTIME_DIR, "http://127.0.0.1:8000", BASE_BROKER)
    http("POST", f"{BASE_BROKER}/v1/admin/reset")
    _, before = http("GET", f"{BASE_MOCK}/stats")

    rows = []
    
    def add_row(case_id, desc, passed, error_code, detail="", side_effect_count=0):
        rows.append({
            "case_id": case_id,
            "category": "prompt_injection",
            "description": desc,
            "expected_decision": "DENY",
            "actual_decision": "DENY" if passed else "ALLOW",
            "error_code": error_code or "",
            "credential_accessed": False,
            "side_effect_count": side_effect_count,
            "passed": passed,
            "detail": detail,
            "timestamp": datetime.now().isoformat(timespec="seconds")
        })

    # Case 1: AA 拒绝签发越权请求
    request = agent.request()
    injected = request.model_copy(update={"resource": "repo/private-repo", "path": "/repos/private-repo/files/secret.txt"})
    code, body = agent.issue(injected)
    err = (body or {}).get("error", {}).get("code")
    add_row("aa_refuse_injection", "AA拒绝签发任务外资源", code == 403 and err == "REQUEST_NOT_AUTHORIZED", err)

    # Case 2: Broker 拒绝篡改请求 (持有者自己签)
    request = agent.request()
    _, cap_body = agent.issue(request)
    cap = SignedCapability.model_validate(cap_body)
    
    # 正常拿到票后，恶意篡改请求内容，并用 Agent 自己的私钥签名
    tampered = request.model_copy(update={"path": "/repos/course-project/files/secret.txt"})
    # 借用 B 的 helper 生成伪造证明
    forged_proof_obj = forged_proof(agent.key, cap, tampered, agent.challenge())
    
    raw = json.dumps({
        "request": tampered.model_dump(mode="json"),
        "capability": cap.model_dump(mode="json"),
        "holder_proof": forged_proof_obj.model_dump(mode="json")
    })
    r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"})
    res = r.json()
    err = res.get("decision", {}).get("code") or res.get("error", {}).get("code")
    add_row("broker_refuse_tamper", "Broker拒绝篡改请求", r.status_code == 403 and err == "REQUEST_HASH_MISMATCH", err)

    # Case 3: Broker 拒绝伪造 Capability (把 read 改 write)
    forged_cap = cap.model_copy(update={"body": cap.body.model_copy(update={"operation": "write_file"})})
    forged_proof_obj = forged_proof(agent.key, forged_cap, request, agent.challenge())
    raw = json.dumps({
        "request": request.model_dump(mode="json"),
        "capability": forged_cap.model_dump(mode="json"),
        "holder_proof": forged_proof_obj.model_dump(mode="json")
    })
    r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"})
    res = r.json()
    err = res.get("decision", {}).get("code") or res.get("error", {}).get("code")
    add_row("broker_refuse_forged_cap", "Broker拒绝伪造Capability", r.status_code == 403 and err == "INVALID_SIGNATURE", err)

    # 验证副作用为 0
    _, after = http("GET", f"{BASE_MOCK}/stats")
    side_effects = after["calls"].get("git", 0) - before["calls"].get("git", 0)
    add_row("zero_side_effects", "所有注入均未产生副作用", side_effects == 0, "", f"side_effects={side_effects}")

    with open("evaluation-dashboard/results/prompt_injection.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["passed"])
    print(f"\n已生成 prompt_injection.csv：{passed}/{len(rows)} passed")

if __name__ == "__main__":
    main()
