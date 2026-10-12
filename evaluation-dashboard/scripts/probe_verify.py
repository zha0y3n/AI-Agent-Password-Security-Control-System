"""探测 /v1/capabilities/verify 的校验行为和错误码。"""
import json
import copy
import requests

BASE = "http://127.0.0.1:8000"

VALID_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "req-probe-verify-001",
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


def issue(req, ttl=60):
    r = requests.post(f"{BASE}/v1/capabilities/issue",
                      json={"request": req, "ttl_seconds": ttl}, timeout=5)
    return r.json()


def verify(capability, request, expected_audience):
    r = requests.post(
        f"{BASE}/v1/capabilities/verify",
        json={
            "capability": capability,
            "request": request,
            "expected_audience": expected_audience,
        },
        timeout=5,
    )
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text


def show(name, code, body):
    print(f"\n--- {name} ---")
    print(f"HTTP {code}")
    if isinstance(body, dict):
        print(json.dumps(body, indent=2, ensure_ascii=False)[:400])
    else:
        print(str(body)[:400])


# 先签发一个合法 Capability
capability = issue(copy.deepcopy(VALID_REQUEST))
print("Issued capability_id:", capability["body"]["capability_id"])

# 1. 正常 verify
code, body = verify(capability, VALID_REQUEST, "broker-01")
show("normal", code, body)

# 2. 篡改签名 value
bad = copy.deepcopy(capability)
bad["signature"]["value"] = "AAAA" + bad["signature"]["value"][4:]
code, body = verify(bad, VALID_REQUEST, "broker-01")
show("tampered_signature", code, body)

# 3. 篡改 expected_audience
code, body = verify(capability, VALID_REQUEST, "broker-99")
show("wrong_audience", code, body)

# 4. 篡改 request.agent_id
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["agent_id"] = "agent-evil"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_agent_id", code, body)

# 5. 篡改 request.task_id
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["task_id"] = "task-evil"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_task_id", code, body)

# 6. 篡改 request.resource
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["resource"] = "repo/private-repo"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_resource", code, body)

# 7. 篡改 request.operation
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["operation"] = "delete_file"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_operation", code, body)

# 8. 篡改 request.credential_id
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["credential_id"] = "aws-prod"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_credential_id", code, body)

# 9. 只改 request.path（触发 REQUEST_HASH_MISMATCH）
bad_req = copy.deepcopy(VALID_REQUEST)
bad_req["path"] = "/repos/course-project/files/keys.txt"
code, body = verify(capability, bad_req, "broker-01")
show("wrong_path_hash_only", code, body)

# 10. 过期
cap_short = issue(copy.deepcopy(VALID_REQUEST), ttl=1)
import time
time.sleep(2)
code, body = verify(cap_short, VALID_REQUEST, "broker-01")
show("expired", code, body)
