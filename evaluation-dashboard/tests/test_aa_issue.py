"""C 连 A 的第一个 pytest：AA 签发接口的 6 个攻击场景。"""
import copy
import requests

BASE = "http://127.0.0.1:8000"

VALID_REQUEST = {
    "protocol_version": "1.0",
    "request_id": "req-c-test-001",
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
    return requests.post(
        f"{BASE}/v1/capabilities/issue",
        json={"request": req, "ttl_seconds": ttl},
        timeout=5,
    )


def test_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_issue_normal():
    r = issue(VALID_REQUEST)
    assert r.status_code == 200
    body = r.json()["body"]
    assert body["task_id"] == "task-demo-001"
    assert body["credential_id"] == "github-prod"
    assert body["credential_epoch"] == 17
    assert body["audience"] == "broker-01"
    assert body["one_time"] is True
    assert body["request_hash"]


def test_issue_unknown_task():
    req = copy.deepcopy(VALID_REQUEST)
    req["task_id"] = "task-not-exist"
    r = issue(req)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "UNKNOWN_TASK"


def test_issue_wrong_resource():
    req = copy.deepcopy(VALID_REQUEST)
    req["resource"] = "repo/private-repo"
    r = issue(req)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "REQUEST_NOT_AUTHORIZED"


def test_issue_wrong_agent():
    req = copy.deepcopy(VALID_REQUEST)
    req["agent_id"] = "agent-evil"
    r = issue(req)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "AGENT_TASK_MISMATCH"


def test_issue_ttl_huge():
    r = issue(VALID_REQUEST, ttl=10**9)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SCHEMA_VALIDATION_FAILED"


def test_issue_ttl_zero():
    r = issue(VALID_REQUEST, ttl=0)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
