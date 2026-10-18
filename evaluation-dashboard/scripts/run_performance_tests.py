"""C 的性能测试：1/10/50/100 并发下的耗时与吞吐。"""
import csv
import json
import statistics
import threading
import time
import requests
import sys
from pathlib import Path
from datetime import datetime

BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"
sys.path.insert(0, str(BROKER_DIR))

from scripts.e2e_demo_lib import Agent, http, SignedCapability

BASE_BROKER = "http://127.0.0.1:8080"
RUNTIME_DIR = BROKER_DIR.parent / ".runtime"

CONCURRENCY_LEVELS = [1, 10, 50, 100]
ROUNDS_PER_LEVEL = 3
REQUESTS_PER_ROUND = 100

def run_round(n_threads, round_id, agent):
    http("POST", f"{BASE_BROKER}/v1/admin/reset")
    
    latencies = []
    lock = threading.Lock()
    
    def worker(idx):
        # 每个请求必须用独立的票据，否则会触发重放拦截
        request = agent.request()
        code, cap_body = agent.issue(request)
        if code != 200:
            return
            
        cap = SignedCapability.model_validate(cap_body)
        proof = agent.proof(cap, request)
        
        raw = json.dumps({
            "request": request.model_dump(mode="json"),
            "capability": cap.model_dump(mode="json"),
            "holder_proof": proof.model_dump(mode="json")
        })
        
        t0 = time.perf_counter()
        try:
            requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"}, timeout=10)
            dt = (time.perf_counter() - t0) * 1000
            with lock:
                latencies.append(dt)
        except Exception:
            pass

    t_start = time.perf_counter()
    threads = []
    remaining = REQUESTS_PER_ROUND
    while remaining > 0:
        batch = min(n_threads, remaining)
        for i in range(batch):
            t = threading.Thread(target=worker, args=(remaining - i,))
            t.start()
            threads.append(t)
        for t in threads[-batch:]:
            t.join()
        remaining -= batch
    total_s = time.perf_counter() - t_start

    if not latencies:
        return {"concurrency": n_threads, "round": round_id, "passed": False}

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95) - 1]
    p99 = latencies[int(len(latencies) * 0.99) - 1]
    throughput = len(latencies) / total_s

    return {
        "concurrency": n_threads,
        "round": round_id,
        "total_requests": len(latencies),
        "total_s": round(total_s, 3),
        "throughput_rps": round(throughput, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
        "passed": len(latencies) == REQUESTS_PER_ROUND,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def main():
    agent = Agent(RUNTIME_DIR, "http://127.0.0.1:8000", BASE_BROKER)
    rows = []
    for level in CONCURRENCY_LEVELS:
        for r in range(1, ROUNDS_PER_LEVEL + 1):
            row = run_round(level, r, agent)
            rows.append(row)
            mark = "PASS" if row["passed"] else "FAIL"
            print(f"[{mark}] n={level:3d} round={r} "
                  f"rps={row['throughput_rps']:8.2f} "
                  f"p50={row['p50_ms']:7.2f}ms p95={row['p95_ms']:7.2f}ms p99={row['p99_ms']:7.2f}ms")

    with open("evaluation-dashboard/results/performance.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("\n已生成 performance.csv")

if __name__ == "__main__":
    main()
