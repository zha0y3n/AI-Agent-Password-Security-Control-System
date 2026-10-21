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

AA 不接受客户端提交的 `TaskContext` 作为授权依据。它仅用 `task_id` 查服务端可信任务库并进行完整精确匹配。AA 对签发请求体限制为 1 MiB，超限返回 413 `REQUEST_TOO_LARGE`；JSON 嵌套过深按 `CANONICALIZATION_ERROR` 返回 400，不能返回 500。

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

## Credential 生命周期状态查询（A 已实现；B 已实现端点，待真实联调）

为避免 AA 使用固定的 `credential_epoch`，A 可在签发前调用 AA 配置中、由可信 `audience` 静态映射出的 Broker 接口：

```text
GET /v1/credentials/{credential_id}/status
Accept: application/json
```

该查询发生在 AgentRequest 已完整匹配 AA 服务端 `AllowedAction` **之后**。Agent 不能指定 URL、audience 或 Credential ID，也不会得到 Broker 管理令牌。B 返回须严格匹配以下对象，不能包含未知字段：

```json
{
  "credential_id": "github-prod",
  "provider": "git",
  "status": "ACTIVE",
  "credential_epoch": 18,
  "created_at": 2000000000,
  "updated_at": 2000000010
}
```

`credential_id` 必须与可信 Action 一致；仅 `status="ACTIVE"` 可签发；AA 将响应中的 `credential_epoch` 直接写入现有、已签名的 CapabilityBody。超时、非 200、重定向、超过 16 KiB、非严格 JSON、未知/缺失字段、非法时间戳、ID 不一致和非 ACTIVE 状态均失败关闭。默认仅允许 HTTPS；本机 Docker/loopback 可显式开启 HTTP，但不能用于生产。

这只缩短状态陈旧窗口，**不替代** B 在执行事务内对 `ACTIVE + epoch` 的原子复核。B 已实现该端点，响应字段与本契约一致；仍需确认实际联调中的 TLS/mTLS 或等效工作负载身份、缓存上限和故障码。A 当前发行错误码为 `CREDENTIAL_STATUS_UNAVAILABLE`、`CREDENTIAL_STATUS_INVALID`、`CREDENTIAL_STATUS_MISMATCH`、`CREDENTIAL_INACTIVE`，需与 B/C 纳入统一错误码表。

## 仍需 A/B 联审的接口

- Broker Challenge API、存活时间、原子消费和错误码；
- Credential Status 查询的传输身份（推荐 mTLS/SPIFFE）、缓存上限、可用性目标和上述 lifecycle 错误码；
- Issuer/Agent/Broker 公钥轮换与旧公钥验证窗口；
- Clock skew 上限及可信时钟来源；
- Capability CAS、故障恢复、幂等冲突和外部 API 成功但状态未落盘的语义；
- 业务 `result_envelope` schema 与 result hash；
- 是否需要 mTLS/SPIFFE 等传输身份；这不替代对象签名。

## 稳定错误码（A 已使用）

主要包括 `REQUEST_NOT_AUTHORIZED`、`UNKNOWN_TASK`、`INVALID_SIGNATURE`、`CAPABILITY_EXPIRED`、`AUDIENCE_MISMATCH`、`REQUEST_BINDING_MISMATCH`、`REQUEST_HASH_MISMATCH`、`CHALLENGE_MISMATCH`、`HOLDER_BINDING_MISMATCH`、`PROOF_EXPIRED`、`UNKNOWN_KEY`、`KEY_REVOKED`。B 可扩展 lifecycle/replay 错误码，但不要把内部 Credential 信息回显给 Agent。
