"""撤销竞态测试：执行与撤销并发发生"""
import csv
import os
import json
import threading
import time
import requests
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../credential-broker/scripts")))
from pathlib import Path
from datetime import datetime
from e2e_demo_lib import Agent, http, SignedCapability

BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"

BASE_BROKER = "http://127.0.0.1:8080"
BASE_MOCK = "http://127.0.0.1:9090"
# 自动尝试从 credential-broker/.env 读取 ADMIN_TOKEN，防止评委忘记 source
_env_path = Path(__file__).resolve().parent.parent.parent / "credential-broker" / ".env"
if _env_path.exists() and not os.environ.get("BROKER_ADMIN_TOKEN"):
    with open(_env_path, "r") as _f:
        for _line in _f:
            if _line.startswith("BROKER_ADMIN_TOKEN="):
                os.environ["BROKER_ADMIN_TOKEN"] = _line.strip().split("=")[1]
                break

ADMIN_TOKEN = os.environ.get("BROKER_ADMIN_TOKEN", "")
RUNTIME_DIR = BROKER_DIR.parent / ".runtime"

ROUNDS = 20

def run_round(round_id, agent):
    # 1. 恢复环境，确保 github-prod 是活着的，且 epoch 对齐
    http("POST", f"{BASE_BROKER}/v1/admin/reset")
    # 重新灌入凭据
    requests.post(f"{BASE_BROKER}/v1/credentials", 
                  json={"credential_id":"github-prod","provider":"git","secret":"mock-git-secret"},
                  headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    # 轮换到 epoch 17
    for _ in range(16):
        requests.post(f"{BASE_BROKER}/v1/credentials/github-prod/rotate", 
                      json={"secret":"mock-git-secret"},
                      headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})

    _, before = http("GET", f"{BASE_MOCK}/stats")
    calls_before = before["calls"].get("git", 0)

    # 2. 准备一份合法的请求包
    request = agent.request()
    _, cap_body = agent.issue(request)
    cap = SignedCapability.model_validate(cap_body)
    proof = agent.proof(cap, request)
    
    raw = json.dumps({
        "request": request.model_dump(mode="json"),
        "capability": cap.model_dump(mode="json"),
        "holder_proof": proof.model_dump(mode="json")
    })

    results = {}
    barrier = threading.Barrier(2)

    def execute_worker():
        barrier.wait()
        try:
            r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"}, timeout=5)
            results["execute"] = (r.status_code, r.json())
        except Exception as e:
            results["execute"] = (500, {"error": str(e)})

    def revoke_worker():
        barrier.wait()
        # 等一丁点时间，让 execute 有概率先拿到锁
        time.sleep(0.002)
        r = requests.post(f"{BASE_BROKER}/v1/credentials/github-prod/revoke", 
                          headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}, timeout=5)
        results["revoke"] = (r.status_code, r.json())

    t1 = threading.Thread(target=execute_worker)
    t2 = threading.Thread(target=revoke_worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    _, after = http("GET", f"{BASE_MOCK}/stats")
    side_effects = after["calls"].get("git", 0) - calls_before

    ex_code, ex_body = results.get("execute", (0, {}))
    ex_decision = ex_body.get("decision", {}).get("allowed", False)
    ex_error = ex_body.get("decision", {}).get("code") or ex_body.get("error", {}).get("code")

    # 安全结果：如果执行成功了，副作用必须是1；如果执行被拒，副作用必须是0
    safe = True
    if ex_code == 200 and ex_decision:
        safe = (side_effects == 1)
    else:
        safe = (side_effects == 0)

    return {
        "round": round_id,
        "case_id": f"revocation_{round_id}",
        "category": "revocation",
        "expected_decision": "ALLOW", 
        "actual_decision": "ALLOW" if ex_decision else "DENY",
        "error_code": ex_error or "",
        "credential_accessed": ex_code == 200 and ex_decision,
        "side_effect_count": side_effects,
        "execute_http": ex_code,
        "execute_allowed": ex_decision,
        "execute_error": ex_error or "",
        "revoke_http": results.get("revoke", (0, {}))[0],
        "safe": safe,
        "passed": safe,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def main():
    agent = Agent(RUNTIME_DIR, "http://127.0.0.1:8000", BASE_BROKER)

    print("=== 自动重置 B 系统环境并灌入初始数据 (防止只能跑一次的问题) ===")
    import subprocess
    root_dir = Path(__file__).resolve().parent.parent.parent
    env = os.environ.copy()
    _env_path = root_dir / "credential-broker" / ".env"
    if _env_path.exists():
        with open(_env_path, "r") as f:
            for line in f:
                if line.startswith("BROKER_ADMIN_TOKEN="):
                    env["BROKER_ADMIN_TOKEN"] = line.strip().split("=")[1]
                    break
    env["MOCK_GIT_TOKEN"] = "mock-git-secret"
    env["MOCK_DB_TOKEN"] = "mock-db-secret"

    subprocess.run(["bash", "scripts/reset.sh"], cwd=str(root_dir / "credential-broker"), env=env, stdout=subprocess.DEVNULL)
    subprocess.run(["bash", "scripts/seed.sh"], cwd=str(root_dir / "credential-broker"), env=env, stdout=subprocess.DEVNULL)
    print("=== 环境重置完毕，开始测试 ===")
    rows = []
    for i in range(1, ROUNDS + 1):
        row = run_round(i, agent)
        rows.append(row)
        mark = "PASS" if row["safe"] else "FAIL"
        print(f"[{mark}] round={i:2d} execute={row['execute_allowed']} "
              f"error={row['execute_error']:25s} side_effects={row['side_effect_count']}")

    with open("evaluation-dashboard/results/revocation.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["safe"])
    print(f"\n已生成 revocation.csv：{passed}/{len(rows)} safe")

if __name__ == "__main__":
    main()
