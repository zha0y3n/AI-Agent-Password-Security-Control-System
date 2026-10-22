"""撤销竞态测试：执行与撤销并发发生"""
import csv
import os
import json
import threading
import time
import random
import requests
import sys
import subprocess
from pathlib import Path
from datetime import datetime

BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"
sys.path.insert(0, str(BROKER_DIR))
from scripts.e2e_demo_lib import Agent, http, SignedCapability

BASE_BROKER = "http://127.0.0.1:8080"
BASE_MOCK = "http://127.0.0.1:9090"

_env_path = BROKER_DIR / ".env"
if _env_path.exists():
    with open(_env_path, "r") as f:
        for _line in f:
            if _line.startswith("BROKER_ADMIN_TOKEN="):
                os.environ["BROKER_ADMIN_TOKEN"] = _line.strip().split("=")[1]
                break
ADMIN_TOKEN = os.environ.get("BROKER_ADMIN_TOKEN", "")

RUNTIME_DIR = BROKER_DIR.parent / ".runtime"
ROOT_DIR = BROKER_DIR.parent
RESULTS_DIR = ROOT_DIR / "evaluation-dashboard" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ROUNDS = 50

def run_round(round_id, agent, force_execute_win):
    # 1. 使用官方脚本保证数据绝对干净
    env = os.environ.copy()
    env["BROKER_ADMIN_TOKEN"] = ADMIN_TOKEN
    env["MOCK_GIT_TOKEN"] = "mock-git-secret"
    env["MOCK_DB_TOKEN"] = "mock-db-secret"
    subprocess.run(["bash", "scripts/reset.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)
    subprocess.run(["bash", "scripts/seed.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)

    _, before = http("GET", f"{BASE_MOCK}/stats")
    calls_before = before["calls"].get("git", 0)

    request = agent.request()
    _, cap_body = agent.issue(request)
    cap = SignedCapability.model_validate(cap_body)
    proof = agent.proof(cap, request)
    raw = json.dumps({"request": request.model_dump(mode="json"), "capability": cap.model_dump(mode="json"), "holder_proof": proof.model_dump(mode="json")})

    results = {}
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    barrier = threading.Barrier(2)

    def execute_worker():
        barrier.wait()
        # 如果是强制撤销先赢，执行稍微睡一下
        if not force_execute_win:
            time.sleep(random.uniform(0.01, 0.03))
        try:
            r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"}, timeout=5)
            results["execute"] = (r.status_code, r.json())
        except Exception as e:
            results["execute"] = (500, {"error": str(e)})

    def revoke_worker():
        barrier.wait()
        # 如果是强制执行先赢，撤销强制睡久一点 (100~200ms)
        if force_execute_win:
            time.sleep(random.uniform(0.1, 0.2))
        try:
            r = requests.post(f"{BASE_BROKER}/v1/credentials/github-prod/revoke", headers=headers, timeout=5)
            results["revoke"] = (r.status_code, r.json())
        except Exception as e:
            results["revoke"] = (500, {"error": str(e)})

    t1 = threading.Thread(target=execute_worker)
    t2 = threading.Thread(target=revoke_worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    _, after = http("GET", f"{BASE_MOCK}/stats")
    side_effects = after["calls"].get("git", 0) - calls_before

    ex_code, ex_body = results.get("execute", (0, {}))
    ex_decision = ex_body.get("decision", {}).get("allowed", False)
    ex_error = ex_body.get("decision", {}).get("code") or ex_body.get("error", {}).get("code")

    safe = True
    if ex_code == 200 and ex_decision:
        safe = (side_effects == 1)
        actual_dec = "ALLOW"
    else:
        safe = (side_effects == 0)
        actual_dec = "DENY"

    return {
        "round": round_id,
        "case_id": f"revocation_{round_id}",
        "category": "revocation",
        "expected_decision": "ALLOW or DENY",
        "actual_decision": actual_dec,
        "error_code": ex_error or "",
        "credential_accessed": ex_code == 200 and ex_decision,
        "side_effect_count": side_effects,
        "safe": safe,
        "passed": safe,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def main():
    print("=== 自动重置 B 系统环境并灌入初始数据 ===")
    env = os.environ.copy()
    env["BROKER_ADMIN_TOKEN"] = ADMIN_TOKEN
    env["MOCK_GIT_TOKEN"] = "mock-git-secret"
    env["MOCK_DB_TOKEN"] = "mock-db-secret"
    subprocess.run(["bash", "scripts/reset.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)
    subprocess.run(["bash", "scripts/seed.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)
    print("=== 环境重置完毕，开始测试 ===")

    agent = Agent(RUNTIME_DIR, "http://127.0.0.1:8000", BASE_BROKER)
    rows = []
    execute_wins = 0
    revoke_wins = 0

    for i in range(1, ROUNDS + 1):
        # 前 25 轮强制执行先赢，后 25 轮强制撤销先赢
        force_execute = i <= (ROUNDS // 2)
        row = run_round(i, agent, force_execute)
        rows.append(row)
        
        if row["actual_decision"] == "ALLOW":
            execute_wins += 1
            winner = "执行先赢"
        else:
            revoke_wins += 1
            winner = "撤销先赢"
            
        mark = "PASS" if row["safe"] else "FAIL"
        print(f"[{mark}] round={i:2d} {winner} | actual={row['actual_decision']} error={row['error_code']} side_effects={row['side_effect_count']}")

    out_path = RESULTS_DIR / "revocation.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["safe"])
    print(f"\n已生成 {out_path}：{passed}/{len(rows)} safe")
    print(f"📊 统计：执行先赢 {execute_wins} 次，撤销先赢 {revoke_wins} 次")

if __name__ == "__main__":
    main()