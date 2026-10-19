"""凭据生命周期测试，输出 credential_lifecycle.csv"""
import csv
import os
import time
import requests
from datetime import datetime

BASE = "http://127.0.0.1:8080"
ADMIN_TOKEN = os.environ.get("BROKER_ADMIN_TOKEN", "")

FIELDS = ["case_id", "category", "description", "expected_http",
          "actual_http", "expected_error", "actual_error",
          "passed", "latency_ms", "timestamp"]


def call(method, path, json_body=None, admin=False):
    headers = {}
    if admin:
        headers["Authorization"] = f"Bearer {ADMIN_TOKEN}"
    start = time.perf_counter()
    r = requests.request(method, f"{BASE}{path}", json=json_body,
                         headers=headers, timeout=10)
    lat = round((time.perf_counter() - start) * 1000, 2)
    try:
        body = r.json()
    except Exception:
        body = {}
    return r.status_code, body, lat


def record(case_id, category, desc, expected_http, expected_error,
           actual_http, actual_body, latency_ms):
    actual_error = None
    if isinstance(actual_body, dict) and "error" in actual_body:
        actual_error = actual_body["error"].get("code")
    passed = (actual_http == expected_http
              and actual_error == expected_error)
    return {
        "case_id": case_id,
        "category": category,
        "description": desc,
        "expected_http": expected_http,
        "actual_http": actual_http,
        "expected_error": expected_error or "",
        "actual_error": actual_error or "",
        "passed": passed,
        "latency_ms": latency_ms,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


def main():
    cid = f"github-prod-{int(time.time())}"
    rows = []

    http, body, lat = call("POST", "/v1/credentials",
                           {"credential_id": cid, "provider": "git",
                            "secret": "mock-git-secret"}, admin=True)
    rows.append(record("create", "lifecycle", "创建凭据",
                       201, None, http, body, lat))

    http, body, lat = call("POST", "/v1/credentials",
                           {"credential_id": cid, "provider": "git",
                            "secret": "mock-git-secret"}, admin=True)
    rows.append(record("create_duplicate", "lifecycle", "重复创建",
                       409, "CONFLICT", http, body, lat))

    http, body, lat = call("POST", "/v1/credentials",
                           {"credential_id": cid + "-x", "provider": "git",
                            "secret": "s"}, admin=False)
    rows.append(record("create_no_auth", "auth", "无 token 创建",
                       401, "UNAUTHORIZED", http, body, lat))

    http, body, lat = call("GET", f"/v1/credentials/{cid}/status")
    rows.append(record("status", "lifecycle", "查询状态",
                       200, None, http, body, lat))

    http, body, lat = call("POST", f"/v1/credentials/{cid}/rotate",
                           {"secret": "rotated-secret"}, admin=True)
    rows.append(record("rotate", "lifecycle", "轮换凭据",
                       200, None, http, body, lat))

    http, body, lat = call("POST", f"/v1/credentials/{cid}/revoke", admin=True)
    rows.append(record("revoke", "lifecycle", "撤销凭据",
                       200, None, http, body, lat))

    http, body, lat = call("POST", f"/v1/credentials/{cid}/revoke", admin=True)
    rows.append(record("revoke_duplicate", "lifecycle", "重复撤销",
                       409, "INVALID_STATE_TRANSITION", http, body, lat))

    http, body, lat = call("GET", "/v1/credentials/not-exist/status")
    rows.append(record("status_missing", "lifecycle", "查询不存在的凭据",
                       404, "CREDENTIAL_NOT_FOUND", http, body, lat))

    http, body, lat = call("GET", "/v1/audit?limit=1000")
    audit_ok = (http == 200 and isinstance(body, dict)
                and len(body.get("records", [])) >= 4)
    rows.append({
        "case_id": "audit_chain", "category": "audit",
        "description": "审计记录 >= 4 条",
        "expected_http": 200, "actual_http": http,
        "expected_error": "", "actual_error": "",
        "passed": audit_ok, "latency_ms": lat,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    })

    with open("evaluation-dashboard/results/credential_lifecycle.csv",
              "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    passed = sum(1 for r in rows if r["passed"])
    for r in rows:
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"[{mark}] {r['case_id']:22s} HTTP {r['actual_http']} "
              f"{r['actual_error'] or ''}")
    print(f"\n已生成 credential_lifecycle.csv：{passed}/{len(rows)} passed")


if __name__ == "__main__":
    main()
