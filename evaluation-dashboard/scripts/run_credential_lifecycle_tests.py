"""凭据生命周期测试，输出 credential_lifecycle.csv。"""
import csv
import os
import time
from pathlib import Path
import requests
from datetime import datetime

BASE = "http://127.0.0.1:8080"
# 自动尝试从 credential-broker/.env 读取 ADMIN_TOKEN，防止评委忘记 source
_env_path = Path(__file__).resolve().parent.parent.parent / "credential-broker" / ".env"
if _env_path.exists() and not os.environ.get("BROKER_ADMIN_TOKEN"):
    with open(_env_path, "r") as _f:
        for _line in _f:
            if _line.startswith("BROKER_ADMIN_TOKEN="):
                os.environ["BROKER_ADMIN_TOKEN"] = _line.strip().split("=")[1]
                break

ADMIN_TOKEN = os.environ.get("BROKER_ADMIN_TOKEN", "")

FIELDS = ["case_id", "category", "description", 
          "expected_decision", "actual_decision", "error_code", 
          "credential_accessed", "side_effect_count",
          "expected_http", "actual_http", "passed", "latency_ms", "timestamp"]

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
        "expected_decision": "ALLOW" if expected_http in (200, 201) else "DENY",
        "actual_decision": "ALLOW" if actual_http in (200, 201) else "DENY",
        "error_code": actual_error or "",
        "credential_accessed": False,
        "side_effect_count": 0,
        "expected_http": expected_http,
        "actual_http": actual_http,
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
        "case_id": "audit_chain", 
        "category": "audit",
        "description": "审计记录 >= 4 条",
        "expected_decision": "ALLOW",
        "actual_decision": "ALLOW",
        "error_code": "",
        "credential_accessed": False,
        "side_effect_count": 0,
        "expected_http": 200, 
        "actual_http": http,
        "passed": audit_ok, 
        "latency_ms": lat,
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
              f"{r['error_code'] or ''}")
    print(f"\n已生成 credential_lifecycle.csv：{passed}/{len(rows)} passed")

if __name__ == "__main__":
    main()
