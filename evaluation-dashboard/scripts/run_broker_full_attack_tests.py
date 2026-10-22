"""Broker 全链路独立攻击测试"""
import csv, json, requests, sys, os
from pathlib import Path
from datetime import datetime

BROKER_DIR = Path(__file__).resolve().parent.parent.parent / "credential-broker"
sys.path.insert(0, str(BROKER_DIR))
from scripts.e2e_demo_lib import Agent, http, SignedCapability, forged_proof, generate_sm2_private_key

BASE_BROKER = "http://127.0.0.1:8080"
BASE_MOCK = "http://127.0.0.1:9090"
RUNTIME_DIR = BROKER_DIR.parent / ".runtime"
ROOT_DIR = BROKER_DIR.parent
RESULTS_DIR = ROOT_DIR / "evaluation-dashboard" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def main():
    import subprocess
    print("=== 自动重置 B 系统环境并灌入初始数据 ===")
    env = os.environ.copy()
    _env_path = BROKER_DIR / ".env"
    if _env_path.exists():
        with open(_env_path, "r") as f:
            for _line in f:
                if _line.startswith("BROKER_ADMIN_TOKEN="):
                    env["BROKER_ADMIN_TOKEN"] = _line.strip().split("=")[1]
                    break
    env["MOCK_GIT_TOKEN"] = "mock-git-secret"
    env["MOCK_DB_TOKEN"] = "mock-db-secret"
    
    headers = {"Authorization": f"Bearer {env['BROKER_ADMIN_TOKEN']}"}
    requests.post(f"{BASE_BROKER}/v1/credentials/github-prod/destroy", headers=headers)
    
    subprocess.run(["bash", "scripts/reset.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)
    subprocess.run(["bash", "scripts/seed.sh"], cwd=str(BROKER_DIR), env=env, stdout=subprocess.DEVNULL)

    agent = Agent(RUNTIME_DIR, "http://127.0.0.1:8000", BASE_BROKER)
    
    rows = []
    
    def add_row(case_id, desc, expected_decision, actual_decision, error_code, passed, credential_accessed, side_effect_count):
        rows.append({
            "case_id": case_id, "category": "broker_full_attack", "description": desc,
            "expected_decision": expected_decision, "actual_decision": actual_decision,
            "error_code": error_code or "", "credential_accessed": credential_accessed,
            "side_effect_count": side_effect_count, "passed": passed,
            "timestamp": datetime.now().isoformat(timespec="seconds")
        })
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {case_id:28s} {error_code or actual_decision} | cred_access={credential_accessed} side_effects={side_effect_count}")

    def exec_bundle_with_metrics(raw):
        _, before = http("GET", f"{BASE_MOCK}/stats")
        calls_before = before["calls"].get("git", 0)
        
        r = requests.post(f"{BASE_BROKER}/v1/execute", data=raw, headers={"Content-Type": "application/json"})
        res = r.json()
        dec = res.get("decision", {}).get("allowed", False)
        err = res.get("decision", {}).get("code") or res.get("error", {}).get("code")
        
        _, after = http("GET", f"{BASE_MOCK}/stats")
        calls_after = after["calls"].get("git", 0)
        side_effects = calls_after - calls_before
        
        # 【修复】直接读取响应体中的权威字段 credential_loaded
        cred_loaded = res.get("credential_loaded", False)
        if "result_envelope" in res:
            cred_loaded = res["result_envelope"].get("credential_loaded", cred_loaded)
        if "receipt" in res and isinstance(res["receipt"], dict):
            cred_loaded = res["receipt"].get("credential_loaded", cred_loaded)
            
        return ("ALLOW" if dec else "DENY"), err, cred_loaded, side_effects

    # 1. 正常请求
    req = agent.request()
    _, cap_body = agent.issue(req)
    cap = SignedCapability.model_validate(cap_body)
    proof = agent.proof(cap, req)
    raw_normal = json.dumps({"request": req.model_dump(mode="json"), "capability": cap.model_dump(mode="json"), "holder_proof": proof.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_normal)
    add_row("normal", "Broker全链路正常请求", "ALLOW", dec, err, dec == "ALLOW", cred_acc, se)

    # 2. 顺序 Replay
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_normal)
    add_row("sequential_replay", "同一张票第二次提交", "DENY", dec, err, dec == "DENY" and err == "CHALLENGE_USED", cred_acc, se)

    # 3. Wrong Holder (偷票)
    thief_key = generate_sm2_private_key()
    req2 = agent.request()
    _, cap_body2 = agent.issue(req2)
    cap2 = SignedCapability.model_validate(cap_body2)
    thief_proof = forged_proof(thief_key, cap2, req2, agent.challenge())
    raw_thief = json.dumps({"request": req2.model_dump(mode="json"), "capability": cap2.model_dump(mode="json"), "holder_proof": thief_proof.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_thief)
    add_row("wrong_holder", "偷票并使用攻击者私钥签名", "DENY", dec, err, dec == "DENY" and err == "INVALID_SIGNATURE", cred_acc, se)

    # 4. 篡改请求资源 (换 resource)
    req3 = agent.request()
    _, cap_body3 = agent.issue(req3)
    cap3 = SignedCapability.model_validate(cap_body3)
    tampered_res = req3.model_copy(update={"resource": "repo/private-repo"})
    proof_res = forged_proof(agent.key, cap3, tampered_res, agent.challenge())
    raw_res = json.dumps({"request": tampered_res.model_dump(mode="json"), "capability": cap3.model_dump(mode="json"), "holder_proof": proof_res.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_res)
    add_row("cross_resource", "篡改请求资源(绑定校验)", "DENY", dec, err, dec == "DENY" and err == "REQUEST_BINDING_MISMATCH", cred_acc, se)

    # 5. 篡改请求任务 (换 task_id)
    req4 = agent.request()
    _, cap_body4 = agent.issue(req4)
    cap4 = SignedCapability.model_validate(cap_body4)
    tampered_task = req4.model_copy(update={"task_id": "task-evil"})
    proof_task = forged_proof(agent.key, cap4, tampered_task, agent.challenge())
    raw_task = json.dumps({"request": tampered_task.model_dump(mode="json"), "capability": cap4.model_dump(mode="json"), "holder_proof": proof_task.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_task)
    add_row("cross_task", "篡改请求任务(绑定校验)", "DENY", dec, err, dec == "DENY" and err == "REQUEST_BINDING_MISMATCH", cred_acc, se)

    # 6. 篡改请求路径 (换 path，触发 HASH 错误)
    req5 = agent.request()
    _, cap_body5 = agent.issue(req5)
    cap5 = SignedCapability.model_validate(cap_body5)
    tampered_path = req5.model_copy(update={"path": "/repos/course-project/files/secret.txt"})
    proof_path = forged_proof(agent.key, cap5, tampered_path, agent.challenge())
    raw_path = json.dumps({"request": tampered_path.model_dump(mode="json"), "capability": cap5.model_dump(mode="json"), "holder_proof": proof_path.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_path)
    add_row("request_hash_mismatch", "篡改实际请求路径(哈希校验)", "DENY", dec, err, dec == "DENY" and err == "REQUEST_HASH_MISMATCH", cred_acc, se)

    # 7. 旧 Epoch 攻击
    req6 = agent.request()
    _, cap_body6 = agent.issue(req6)
    cap6 = SignedCapability.model_validate(cap_body6)
    proof6 = agent.proof(cap6, req6)
    
    requests.post(f"{BASE_BROKER}/v1/credentials/github-prod/rotate", json={"secret": "new-secret"}, headers=headers)
    
    raw_old = json.dumps({"request": req6.model_dump(mode="json"), "capability": cap6.model_dump(mode="json"), "holder_proof": proof6.model_dump(mode="json")})
    dec, err, cred_acc, se = exec_bundle_with_metrics(raw_old)
    add_row("old_epoch", "旧 Credential Epoch", "DENY", dec, err, dec == "DENY" and err == "CREDENTIAL_EPOCH_MISMATCH", cred_acc, se)

    out_path = RESULTS_DIR / "broker_full_attack.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    passed = sum(1 for r in rows if r["passed"])
    print(f"\n已生成 {out_path}：{passed}/{len(rows)} passed")

if __name__ == "__main__":
    main()