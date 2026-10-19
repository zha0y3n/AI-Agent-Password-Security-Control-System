"""并发重放测试：100 并发同一张票，只允许成功 1 次"""
import csv
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

# 把 B 的目录加到 sys.path
BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"

BASE_BROKER = "http://127.0.0.1:8080"
BASE_MOCK = "http://127.0.0.1:9090"
RUNTIME_DIR = BROKER_DIR.parent / ".runtime"

CONCURRENCY_LEVELS = [10, 50, 100, 200]
ROUNDS_PER_LEVEL = 3

def run_round(n_threads, round_id, agent):
    http("POST", f"{BASE_BROKER}/v1/admin/reset")
    _, before = http("GET", f"{BASE_MOCK}/stats")
    calls_before = before["calls"].get("git", 0)

    # 1. 申请一张票
    request = agent.request()
    code, cap_body = agent.issue(request)
    if code != 200:
        return {"concurrency": n_threads, "round": round_id, "passed": False, "message": "issue failed"}

    # 2. 生成完整请求包
    cap = SignedCapability.model_validate(cap_body)
    proof = agent.proof(cap, request)
    
    # 手动组装成 B 需要的 JSON（防止格式差异）
    raw_dict = {
        "request": request.model_dump(mode="json"),
        "capability": cap.model_dump(mode="json"),
        "holder_proof": proof.model_dump(mode="json")
    }
    raw = json.dumps(raw_dict)

    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_threads)

    def worker():
        barrier.wait()
        try:
            r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"}, timeout=10)
            with lock:
                results.append((r.status_code, r.json()))
        except Exception as e:
            with lock:
                results.append((500, {"error": str(e)}))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    t0 = time.perf_counter()
    for t in threads: t.start()
    for t in threads: t.join()
    duration = time.perf_counter() - t0

    success_count = sum(1 for code, body in results if code == 200)
    replay_count = sum(1 for code, body in results if code == 403 and body.get("decision", {}).get("code") == "CHALLENGE_USED")
    other_count = n_threads - success_count - replay_count

    _, after = http("GET", f"{BASE_MOCK}/stats")
    calls_after = after["calls"].get("git", 0)
    side_effects = calls_after - calls_before

    passed = (success_count == 1) and (side_effects == 1)

    return {
        "concurrency": n_threads,
        "round": round_id,
        "case_id": f"concurrency_{n_threads}_{round_id}",
        "category": "concurrency",
        "total_requests": n_threads,
        "success_count": success_count,
        "actual_decision": "ALLOW" if success_count > 0 else "DENY",
        "replay_reject_count": replay_count,
        "other_count": other_count,
        "error_code": "CHALLENGE_USED" if replay_count > 0 else "",
        "credential_accessed": success_count > 0,
        "side_effect_count": side_effects,
        "duration_s": round(duration, 3),
        "passed": passed,
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
    for level in CONCURRENCY_LEVELS:
        for r in range(1, ROUNDS_PER_LEVEL + 1):
            row = run_round(level, r, agent)
            rows.append(row)
            mark = "PASS" if row["passed"] else "FAIL"
            print(f"[{mark}] n={level:3d} round={r} "
                  f"success={row['success_count']} "
                  f"replay={row['replay_reject_count']} "
                  f"side_effects={row['side_effect_count']} "
                  f"duration={row['duration_s']}s")

    with open("evaluation-dashboard/results/concurrency.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["passed"])
    print(f"\n已生成 concurrency.csv：{passed}/{len(rows)} passed")

if __name__ == "__main__":
    main()
