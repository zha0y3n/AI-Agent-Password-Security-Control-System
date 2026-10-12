# A → B 接口交接

## 立即交给 B 的产物

1. `shared/schemas/execution-bundle.schema.json`：Agent 发给 Broker 的 request + capability + holder_proof。
2. `shared/schemas/signed-capability.schema.json`、`holder-proof.schema.json`、`signed-receipt.schema.json`。
3. `shared/test-vectors/sm2-sm3-v1.json`：Python/Go 字节级互操作向量。
4. `docs/crypto-protocol.md`：Canonical JSON、SM2 ID、签名输入、DER/base64url 约定。
5. AA 公钥查询：`GET /v1/public-keys/{key_id}`。
6. 签发接口：`POST /v1/capabilities/issue`。
7. 互操作诊断：`POST /v1/capabilities/verify`、`POST /v1/receipts/verify`（只验签，不代表 B 已执行）。

## 签发请求

```json
{
  "request": {
    "protocol_version": "1.0",
    "request_id": "req-demo-001",
    "agent_id": "agent-demo-01",
    "agent_key_id": "agent-key-demo-01",
    "task_id": "task-demo-001",
    "service": "git",
    "resource": "repo/course-project",
    "operation": "read_file",
    "method": "GET",
    "path": "/repos/course-project/files/README.md",
    "query": {},
    "body": null,
    "credential_id": "github-prod"
  },
  "ttl_seconds": 60
}
```

AA 不接受客户端提交的 `TaskContext` 作为授权依据。它仅用 `task_id` 查服务端可信任务库并进行完整精确匹配。

## B 的强制校验顺序

B 可以在不泄露细节的前提下统一返回拒绝，但内部至少应完成以下顺序：

1. 严格 JSON/schema 校验，拒绝重复/未知字段和非规范类型。
2. 校验 signature 元数据、可信 issuer、issuer key 状态/有效期、SM2 签名。
3. 校验 Capability `issued_at/expires_at/ttl` 和目标 audience。
4. 用实际 AgentRequest 重算 SM3，并逐项比较 Agent/Task/Service/Resource/Operation/Credential ID。
5. 校验 Holder Proof 元数据、Agent 公钥状态、签名、CapabilityHash、RequestHash、Audience、Challenge 和 proof 时间窗。
6. 在可信事务中检查并原子消费 Challenge，防止 proof 重放。
7. 在同一授权线性化事务中检查 Credential 状态和当前 epoch、Capability 状态/nonce，并 CAS 到 `CONSUMING`。
8. 仅在以上全部成功后从 Vault 解密 Credential 并调用受保护 API。
9. 使用 `capability_id` 作为下游幂等键；记录结果，签发 Receipt，完成 `CONSUMED`。

任一步失败都不得读取 Credential 明文或产生业务副作用。

## 仍需 A/B 联审的接口

- Broker Challenge API、存活时间、原子消费和错误码；
- AA 如何安全取得当前 Credential epoch（首轮固定可信策略中为 17，Broker 仍须按实时值复核）；
- Issuer/Agent/Broker 公钥轮换与旧公钥验证窗口；
- Clock skew 上限及可信时钟来源；
- Capability CAS、故障恢复、幂等冲突和外部 API 成功但状态未落盘的语义；
- 业务 `result_envelope` schema 与 result hash；
- 是否需要 mTLS/SPIFFE 等传输身份；这不替代对象签名。

## 稳定错误码（A 已使用）

主要包括 `REQUEST_NOT_AUTHORIZED`、`UNKNOWN_TASK`、`INVALID_SIGNATURE`、`CAPABILITY_EXPIRED`、`AUDIENCE_MISMATCH`、`REQUEST_BINDING_MISMATCH`、`REQUEST_HASH_MISMATCH`、`CHALLENGE_MISMATCH`、`HOLDER_BINDING_MISMATCH`、`PROOF_EXPIRED`、`UNKNOWN_KEY`、`KEY_REVOKED`。B 可扩展 lifecycle/replay 错误码，但不要把内部 Credential 信息回显给 Agent。
