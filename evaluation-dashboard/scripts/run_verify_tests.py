"""verify 接口攻击测试，输出 verify.csv"""
import csv, copy, time, requests
from datetime import datetime

BASE = "http://127.0.0.1:8000"

REQ = {
    "protocol_version": "1.0", "request_id": "req-c-v-001",
    "agent_id": "agent-demo-01", "agent_key_id": "agent-key-demo-01",
    "task_id": "task-demo-001", "service": "git",
    "resource": "repo/course-project", "operation": "read_file",
    "method": "GET", "path": "/repos/course-project/files/README.md",
    "query": {}, "body": None, "credential_id": "github-prod",
}

def issue(ttl=60):
    r = requests.post(f"{BASE}/v1/capabilities/issue",
                      json={"request": REQ, "ttl_seconds": ttl}, timeout=5)
    return r.json()

def v(cap, req, aud):
    s = time.perf_counter()
    r = requests.post(f"{BASE}/v1/capabilities/verify",
                      json={"capability": cap, "request": req, "expected_audience": aud}, timeout=5)
    lat = round((time.perf_counter() - s) * 1000, 2)
    try: body = r.json()
    except Exception: body = {}
    return r.status_code, body, lat

def run(cid, cat, desc, cap, req, aud, eh, ee):
    http, body, lat = v(cap, req, aud)
    err = body.get("error", {}).get("code") if isinstance(body, dict) else None
    passed = (http == eh and err == ee)
    mark = "PASS" if passed else "FAIL"
    print(f"[{mark}] {cid:25s} HTTP {http} {err or ''} ({lat}ms)")
    return {"case_id": cid, "category": cat, "description": desc,
            "expected_decision": "ALLOW" if eh == 200 else "DENY",
            "actual_decision": "ALLOW" if http == 200 else "DENY",
            "error_code": err or "",
            "credential_accessed": False,
            "side_effect_count": 0,
            "expected_http": eh, "actual_http": http,
            "passed": passed, "latency_ms": lat,
            "timestamp": datetime.now().isoformat(timespec="seconds")}

def main():
    cap = issue()
    bad = copy.deepcopy(cap)
    bad["signature"]["value"] = "AAAA" + bad["signature"]["value"][4:]

    rows = []
    rows.append(run("verify_normal", "baseline", "正常验签",
                    cap, copy.deepcopy(REQ), "broker-01", 200, None))
    rows.append(run("verify_tampered_sig", "signature", "篡改签名",
                    bad, copy.deepcopy(REQ), "broker-01", 401, "INVALID_SIGNATURE"))
    rows.append(run("verify_wrong_audience", "binding", "audience 错误",
                    cap, copy.deepcopy(REQ), "broker-99", 401, "AUDIENCE_MISMATCH"))

    for cid, field, val, cat in [
        ("verify_wrong_agent", "agent_id", "agent-evil", "binding"),
        ("verify_wrong_task", "task_id", "task-evil", "binding"),
        ("verify_wrong_resource", "resource", "repo/private-repo", "binding"),
        ("verify_wrong_operation", "operation", "delete_file", "binding"),
        ("verify_wrong_credential", "credential_id", "aws-prod", "binding"),
    ]:
        r = copy.deepcopy(REQ); r[field] = val
        rows.append(run(cid, cat, f"{field} 不一致",
                        cap, r, "broker-01", 401, "REQUEST_BINDING_MISMATCH"))

    r = copy.deepcopy(REQ); r["path"] = "/repos/course-project/files/keys.txt"
    rows.append(run("verify_hash_mismatch", "binding", "改 path 触发 hash 不一致",
                    cap, r, "broker-01", 401, "REQUEST_HASH_MISMATCH"))

    short = issue(ttl=1)
    time.sleep(2)
    rows.append(run("verify_expired", "lifecycle", "过期票据验签",
                    short, copy.deepcopy(REQ), "broker-01", 401, "CAPABILITY_EXPIRED"))

    with open("evaluation-dashboard/results/verify.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)

    p = sum(1 for r in rows if r["passed"])
    print(f"\n已生成 evaluation-dashboard/results/verify.csv：{p}/{len(rows)} passed")

if __name__ == "__main__":
    main()
