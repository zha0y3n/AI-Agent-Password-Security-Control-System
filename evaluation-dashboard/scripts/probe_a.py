"""探测 A 的几种拒绝行为，看真实 HTTP 状态码 + JSON 结构"""
import json
import copy
import requests

BASE = "http://127.0.0.1:8000"

VALID_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "req-probe-001",
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
    try:
        body = r.json()
    except Exception:
        body = r.text
    return r.status_code, body

def show(name, req, ttl=60):
    code, body = issue(req, ttl)
    print(f"\n--- {name} ---")
    print(f"HTTP {code}")
    if isinstance(body, dict):
        print(json.dumps(body, indent=2, ensure_ascii=False)[:600])
    else:
        print(body[:600])

# 1. 正常
show("normal", VALID_REQUEST)

# 2. 未知任务
bad = copy.deepcopy(VALID_REQUEST)
bad["task_id"] = "task-not-exist"
show("unknown_task", bad)

# 3. 错误资源
bad = copy.deepcopy(VALID_REQUEST)
bad["resource"] = "repo/private-repo"
show("wrong_resource", bad)

# 4. 错误 agent
bad = copy.deepcopy(VALID_REQUEST)
bad["agent_id"] = "agent-evil"
show("wrong_agent", bad)

# 5. 未知 key
bad = copy.deepcopy(VALID_REQUEST)
bad["agent_key_id"] = "agent-key-not-exist"
show("unknown_key", bad)

# 6. ttl 超长
show("ttl_huge", VALID_REQUEST, ttl=10**9)

# 7. ttl=0
show("ttl_zero", VALID_REQUEST, ttl=0)
