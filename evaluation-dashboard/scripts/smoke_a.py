"""连 A 的冒烟脚本"""
import json
import requests
from datetime import datetime

BASE = "http://127.0.0.1:8000"

VALID_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "req-c-smoke-001",
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


def check_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    print(f"[health] {r.status_code} {r.json()}")
    return r.status_code == 200


def check_public_key():
    r = requests.get(f"{BASE}/v1/public-keys/aa-key-demo-01", timeout=5)
    data = r.json()
    print(f"[public-key] key_id={data.get('key_id')} status={data.get('status')}")
    return r.status_code == 200


def check_issue_capability():
    payload = {"request": VALID_REQUEST, "ttl_seconds": 60}
    r = requests.post(f"{BASE}/v1/capabilities/issue", json=payload, timeout=5)
    print(f"[issue] HTTP {r.status_code}")
    if r.status_code != 200:
        print(f"  body: {r.text[:300]}")
        return False
    data = r.json()
    body = data.get("body", {})
    print(f"  capability_id = {body.get('capability_id')}")
    print(f"  request_hash  = {body.get('request_hash')}")
    print(f"  credential_id = {body.get('credential_id')}")
    print(f"  epoch         = {body.get('credential_epoch')}")
    print(f"  audience      = {body.get('audience')}")
    print(f"  expires_at    = {body.get('expires_at')}")
    print(f"  one_time      = {body.get('one_time')}")
    return True


if __name__ == "__main__":
    print(f"=== C smoke test @ {datetime.now().isoformat(timespec='seconds')} ===")
    ok = True
    ok &= check_health()
    ok &= check_public_key()
    ok &= check_issue_capability()
    print(f"\n结果：{'全部通过' if ok else '有失败'}")
