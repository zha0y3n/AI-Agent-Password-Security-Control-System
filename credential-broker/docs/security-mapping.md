# 威胁与防御对照（Broker 侧）

> 攻击者能力和信任假设见 [docs/threat-model.md](../../docs/threat-model.md)。本表只列出 **Broker 负责拦截**的部分，写明每类攻击在哪一步被拦下、返回什么码、由哪个测试或演示证明。
> 测试路径相对于 `credential-broker/internal/`。演示指 `scripts/e2e-demo.py`（真实 HTTP，A 的 AA 签发）。
> 本表是 B 的单元测试和联调结论，**不是 C 的系统实验结果**。C 的实验要以实际副作用计数为准。

## 1. 伪造与篡改

| 攻击 | 拦截位置 | 拒绝码 | 证据 |
|---|---|---|---|
| 修改 Capability 的任意签名字段（如 `read_file` 改成 `write_file`） | `capability_signature` | `INVALID_SIGNATURE` | `verifier/steps_test.go` `tampered_capability`；演示“篡改 Capability” |
| 用 Agent 私钥冒充 AA 签 Capability | `capability_signature` | `INVALID_SIGNATURE` | `capability_signed_by_agent` |
| 非可信 AA 签发 | `capability_signature` | `UNTRUSTED_ISSUER` | `untrusted_issuer` |
| 签名 key_id 与 body 不一致 / 未知签名密钥 | `capability_signature` | `SIGNATURE_KEY_MISMATCH` / `UNKNOWN_KEY` | `signature_key_mismatch`、`unknown_issuer_key` |
| 夹带 schema 外字段（如 `task_context: {trusted: true}`） | `schema` | `SCHEMA_VALIDATION_FAILED` | `schema_unknown_field`、`protocol/schema_test.go` |
| 非规范 JSON（浮点、重复键、BOM、非法转义） | `schema` | `CANONICALIZATION_ERROR` | `canonical_garbage`、`canonical/canonical_test.go` `TestParseRejects` |
| 伪造或篡改 Execution Receipt | A 的 `ReceiptVerifier` | 验签失败 | `scripts/verify-a-receipt.py`（`make interop`，含篡改副本） |

## 2. 请求替换与越权

| 攻击 | 拦截位置 | 拒绝码 | 证据 |
|---|---|---|---|
| 拿到合法 Capability，但提交另一个资源的请求 | `request_binding` | `REQUEST_BINDING_MISMATCH` | `request_wrong_resource` |
| 只改请求路径（如读 `secret.txt`），并用自己的私钥重签 Holder Proof | `request_binding`（Broker 重算摘要） | `REQUEST_HASH_MISMATCH` | `request_hash_path_only`；演示“篡改请求路径” |
| 请求能通过绑定校验，但路径、方法或 body 有歧义（多余 query、多余字段、跨仓库路径、`..` 段） | `execution_plan` / `schema` | `UNSUPPORTED_OPERATION` / `SCHEMA_VALIDATION_FAILED` | `verifier/plan_test.go` `TestMapRequestRejects`（15 种） |
| 提示注入，让 Agent 请求任务之外的资源 | **AA**（拒绝签发），Broker 是第二道防线 | AA 拒绝 | 演示“提示注入” |

## 3. 窃取与冒用

| 攻击 | 拦截位置 | 拒绝码 | 证据 |
|---|---|---|---|
| 偷到 Capability，用攻击者自己的私钥签 Holder Proof | `holder_proof` | `INVALID_SIGNATURE` | `proof_wrong_holder`；演示“被窃取的 Capability” |
| 用 AA 私钥签 Holder Proof | `holder_proof` | `INVALID_SIGNATURE` | `proof_signed_by_aa` |
| Holder Proof 绑定的是另一张 Capability，或 capability_hash 不对 | `holder_proof` | `HOLDER_BINDING_MISMATCH` | `proof_for_other_capability`、`proof_wrong_capability_hash` |
| Agent 公钥已被吊销 | `holder_proof`（公钥查找） | `KEY_REVOKED` | `TestExecuteRevokedAgentKey` |
| 把发给其他 Broker 的 Capability 或 Proof 拿到本 Broker 用 | `capability_validity` / `holder_proof` | `AUDIENCE_MISMATCH` | `capability_wrong_audience`、`proof_wrong_audience` |
| 伪造 Challenge（不是本 Broker 签发的） | `challenge` | `CHALLENGE_UNKNOWN` | `challenge_not_issued`；演示“伪造 Challenge” |
| 用发给其他 Agent 的 Challenge | `challenge` | `CHALLENGE_WRONG_AGENT` | `challenge_for_other_agent` |
| 绕过 Broker，直接调用受保护服务 | 上游鉴权（Agent 没有 Credential） | 401，`auth_failures` 计数增加 | `upstream/upstream_test.go` `TestRequiresCorrectCredential` |

## 4. 时间与重放

| 攻击 | 拦截位置 | 拒绝码 | 证据 |
|---|---|---|---|
| 过期的 Capability 或 Holder Proof | `capability_validity` / `holder_proof` | `CAPABILITY_EXPIRED` / `PROOF_EXPIRED` | `capability_expired`、`proof_expired` |
| 签发时间在未来（超出 5 秒偏差） | 同上 | `CAPABILITY_NOT_YET_VALID` | `capability_not_yet_valid` |
| 原样重放整个 bundle | `challenge` | `CHALLENGE_USED` | `TestReplaySameBundle`；演示“原样重放” |
| 同一 Capability 换新 Challenge 再提交 | `atomic_consume`（已是 `CONSUMED`） | 不拒绝，返回原结果和**同一张回执**，上游不再调用 | `TestReplaySameCapabilityNewChallenge`、`TestReceiptReplayIsIdentical`；演示“幂等返回同一回执” |
| 两张不同的 Capability 复用同一 nonce | `atomic_consume`（nonce 唯一索引） | `CAPABILITY_NONCE_REUSED` | `TestCapabilityNonceReuseDenied`、`TestNonceIsSingleUse` |
| 同一 Capability 携带不同请求 | `request_binding`（摘要不符）；绕过后由 `atomic_consume` 兜底 | `REQUEST_HASH_MISMATCH` / `IDEMPOTENCY_CONFLICT` | `capability/consume_test.go` `TestConsumeLifecycleAndIdempotency` |
| 同一 Capability 并发提交 N 次 | `atomic_consume`（写锁 + CAS） | 1 次成功，其余 `REPLAY_IN_PROGRESS` 或返回原结果 | `TestConcurrentReplayExactlyOneWinner`（100 并发）、`TestConcurrentReplayWriteSideEffectOnce`（20 个完整 bundle，写入 1 次） |
| 之前执行失败的 Capability 再试一次 | `atomic_consume` | `CAPABILITY_ALREADY_FAILED` | `TestFailedCapabilityCannotBeReused` |

## 5. Credential 生命周期

| 攻击 | 拦截位置 | 拒绝码 | 证据 |
|---|---|---|---|
| 用 Credential 轮换前签发的 Capability | `atomic_consume`（epoch） | `CREDENTIAL_EPOCH_MISMATCH` | `credential_old_epoch`、`TestOldEpochRejected`；联调时轮换到 epoch 18 后验证过 |
| Credential 已撤销、禁用或标记泄露 | `atomic_consume`（状态） | `CREDENTIAL_INACTIVE` | `credential_revoked`、`TestRevokedCredentialDeniedBeforeDecrypt` |
| Disable 再 Enable，期望旧 Capability 复活 | epoch 已加一 | `CREDENTIAL_EPOCH_MISMATCH` | `credential/lifecycle_test.go` `TestDisableEnableDoesNotReviveOldEpoch` |
| 撤销与消费并发竞态 | 同一把 SQLite 写锁，线性化 | 撤销在前则 `CREDENTIAL_INACTIVE` | `TestRevocationRaceIsLinearizable`（40 轮，用审计序号核对先后） |
| 消费之后、解密之前被撤销 | `credential_decrypt`（再检查一次 + AAD 绑定 epoch） | `CREDENTIAL_UNAVAILABLE`，Capability 进入 `FAILED` | `execution/executor.go`；`vault/vault_test.go` `TestVaultBindsMetadata` |

## 6. 机密性

| 攻击 | 防御 | 证据 |
|---|---|---|
| 从 API 响应、日志、审计中读到 Credential | `secret.Secret` 永远输出 `[REDACTED]`；访问日志不记请求体和请求头；审计不含明文和密文 | `vault/vault_test.go` `TestSecretNeverPrinted`、`logging/logging_test.go` `TestRedaction`、`api/execute_test.go` 与 `api/api_test.go` 的泄露断言；compose 日志人工检查 |
| 偷到数据库文件 | 只有 SM4-GCM 密文，`K_V` 不在库里；文件权限 0600 | `TestVaultBindsMetadata` |
| 把一个 Credential 的密文换到另一个 ID 或 epoch 下 | AAD 绑定 id、provider、epoch，并带长度前缀 | `TestVaultBindsMetadata`、`TestAADIsUnambiguous` |
| 被拒绝的请求诱使 Broker 读取 Credential | 拒绝发生在 `Credentials.Open` 之前，这一点由代码结构保证 | `execution/executor_test.go` `TestDeniedRequestNeverTouchesCredential`；`verifier/steps_test.go` `TestExecuteDenials` 的 23 类拒绝逐条断言未加载 Credential、上游调用次数为 0 |

## 7. 证据完整性

| 攻击 | 防御 | 证据 |
|---|---|---|
| 修改、删除、重排审计条目 | SM3 哈希链 | `evidence/audit_test.go` `TestChainTamperDetection` |
| 把审计回滚或截断到较早状态 | SM2 签名检查点的 `seq` 超过现有条目数 | 同上；`GET /v1/audit/verify` |
| 状态变了却没有留痕 | 审计与状态变更在同一事务内提交 | `TestLifecycleIsAudited`、`TestDecisionsAreAudited` |
| 声称执行了实际没执行的操作，或反过来 | Broker 签名的 Receipt 绑定 capability_id、request_hash 和 result_envelope | `verifier/receipt_test.go` |

## 8. Broker 不防御的情况

以下情况超出信任假设，对应 [threat-model.md](../../docs/threat-model.md) 的“非目标 / 剩余风险”：

- **Broker 进程或主机被完全控制。** 攻击者能读到 `K_V`、私钥和内存中的明文。
- **可信任务本身授权过宽。** Broker 只执行 AA 签过的请求，不判断任务是否合理。
- **Agent 的 Holder 私钥所在主机被控制。** 攻击者可以在 Capability 有效期内冒充 Agent，但范围仍受 Capability 限制，且每张只能用一次。
- **上游执行之后 Broker 崩溃。** 副作用至多一次，但可能没有回执，见 [architecture.md §5.3](architecture.md#53-为什么不是严格的-exactly-once)。
- **最后一个检查点之后的尾部条目被截断。** 要到下一个检查点才能发现。
