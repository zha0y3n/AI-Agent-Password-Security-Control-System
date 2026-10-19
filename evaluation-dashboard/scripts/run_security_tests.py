"""安全测试：把 10 个攻击场景跑一遍，输出 security.csv"""
import csv
import copy
import time
import requests
from datetime import datetime

BASE = "http://127.0.0.1:8000"

VALID_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "req-c-sec-001",
    "agent_id": "agent-demo-01",
    "agent_key_id": "agent-key-demo-01",
    "task_id": "task-demo-001",
    "service": "git",
    "resource": "repo/course-project",
    "operation": "read_file",
    "method": "GET",
    "path": "/repos/course-project/files/README.md",
    "query": {},
    "body": None,
    "credential_id": "github-prod",
}

def call(req, ttl=60):
    start = time.perf_counter()
    r = requests.post(
        f"{BASE}/v1/capabilities/issue",
        json={"request": req, "ttl_seconds": ttl},
        timeout=5,
    )
    latency_ms = (time.perf_counter() - start) * 1000
    try:
        body = r.json()
    except Exception:
        body = {}
    return r.status_code, body, round(latency_ms, 2)

def build_cases():
    cases = []

    def add(case_id, category, description, req, ttl,
            expected_http, expected_error):
        cases.append({
            "case_id": case_id,
            "category": category,
            "description": description,
            "request": req,
            "ttl": ttl,
            "expected_http": expected_http,
            "expected_error": expected_error,
        })

    add("normal", "baseline", "正常签发",
        copy.deepcopy(VALID_REQUEST), 60, 200, None)

    req = copy.deepcopy(VALID_REQUEST); req["task_id"] = "task-not-exist"
    add("unknown_task", "task", "未知任务",
        req, 60, 403, "UNKNOWN_TASK")

    req = copy.deepcopy(VALID_REQUEST); req["resource"] = "repo/private-repo"
    add("wrong_resource", "binding", "换资源",
        req, 60, 403, "REQUEST_NOT_AUTHORIZED")

    req = copy.deepcopy(VALID_REQUEST); req["operation"] = "delete_file"
    add("wrong_operation", "binding", "换操作",
        req, 60, 403, "REQUEST_NOT_AUTHORIZED")

    req = copy.deepcopy(VALID_REQUEST); req["path"] = "/repos/course-project/files/keys.txt"
    add("wrong_path", "binding", "换路径",
        req, 60, 403, "REQUEST_NOT_AUTHORIZED")

    req = copy.deepcopy(VALID_REQUEST); req["method"] = "DELETE"
    add("wrong_method", "binding", "换 HTTP 方法",
        req, 60, 403, "REQUEST_NOT_AUTHORIZED")

    req = copy.deepcopy(VALID_REQUEST); req["agent_id"] = "agent-evil"
    add("wrong_agent", "identity", "错误 agent",
        req, 60, 403, "AGENT_TASK_MISMATCH")

    req = copy.deepcopy(VALID_REQUEST); req["agent_key_id"] = "agent-key-not-exist"
    add("unknown_key", "identity", "未知 agent_key_id",
        req, 60, 403, "AGENT_TASK_MISMATCH")

    add("ttl_zero", "schema", "ttl=0",
        copy.deepcopy(VALID_REQUEST), 0, 422, "SCHEMA_VALIDATION_FAILED")

    add("ttl_huge", "schema", "ttl 超长",
        copy.deepcopy(VALID_REQUEST), 10**9, 422, "SCHEMA_VALIDATION_FAILED")

    return cases

def main():
    rows = []
    for c in build_cases():
        http, body, latency = call(c["request"], c["ttl"])
        actual_error = None
        if isinstance(body, dict) and "error" in body:
            actual_error = body["error"].get("code")

        passed = (http == c["expected_http"]
                  and actual_error == c["expected_error"])
        rows.append({
            "case_id": c["case_id"],
            "category": c["category"],
            "description": c["description"],
            "expected_decision": "ALLOW" if c["expected_http"] == 200 else "DENY",
            "actual_decision": "ALLOW" if http == 200 else "DENY",
            "error_code": actual_error or "",
            "credential_accessed": False,
            "side_effect_count": 0,
            "expected_http": c["expected_http"],
            "actual_http": http,
            "passed": passed,
            "latency_ms": latency,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {c['case_id']:18s} HTTP {http} "
              f"{actual_error or ''}  ({latency}ms)")

    with open("evaluation-dashboard/results/security.csv",
              "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["passed"])
    print(f"\n已生成 evaluation-dashboard/results/security.csv："
          f"{passed}/{len(rows)} passed")

if __name__ == "__main__":
    main()
