# 统一错误码表

本表用于 A（AA 签发）、B（Broker 执行）和 C（实验 CSV）对同一拒绝语义使用同一名称。HTTP 状态只是传输层映射，不能替代错误码。

## A：AA 签发阶段

| 错误码 | HTTP | 含义 |
|---|---:|---|
| `REQUEST_TOO_LARGE` | 413 | 请求体超过 AA 的 1 MiB 上限 |
| `CANONICALIZATION_ERROR` | 400 | 非 ZTCANON-JSON-v1：重复 key、浮点、越界整数、非法 UTF-8、JSON 嵌套过深 |
| `SCHEMA_VALIDATION_FAILED` | 422 | Pydantic 模型校验失败 |
| `UNKNOWN_TASK` | 403 | `task_id` 不在服务端可信任务库 |
| `DUPLICATE_TASK` | 403 | 可信任务库存在重复 `task_id` |
| `TASK_NOT_ACTIVE` | 403 | 任务不是 `ACTIVE` |
| `TASK_OUTSIDE_VALIDITY` | 403 | 当前时间不在任务有效期内 |
| `AGENT_TASK_MISMATCH` | 403 | Agent/Key 不属于该任务 |
| `REQUEST_NOT_AUTHORIZED` | 403 | 请求没有精确匹配一个可信 `AllowedAction` |
| `TTL_EXCEEDS_POLICY` | 403 | 请求 TTL 超过 Action 的 `max_ttl_seconds` |
| `TTL_EXCEEDS_TASK` | 403 | Capability 会超出任务有效期 |
| `CREDENTIAL_STATUS_UNAVAILABLE` | 403 | Status 超时、网络错误、重定向、非 200，或未配置 audience 端点 |
| `CREDENTIAL_STATUS_INVALID` | 403 | Status 响应超过 16 KiB、非严格 JSON、未知/缺失字段、类型或时间戳非法 |
| `CREDENTIAL_STATUS_MISMATCH` | 403 | Status 返回的 `credential_id` 与可信 Action 不一致 |
| `CREDENTIAL_INACTIVE` | 403 | Status 不是 `ACTIVE` |

## A：参考验签

| 错误码 | HTTP | 含义 |
|---|---:|---|
| `INVALID_SIGNATURE` | 401 | SM2 验签失败或 DER 非法 |
| `INVALID_SIGNATURE_ENCODING` | 401 | 签名编码不是 base64url-no-padding |
| `SIGNATURE_KEY_MISMATCH` | 401 | 签名 `key_id` 与签名体不一致 |
| `UNTRUSTED_ISSUER` | 401 | Capability issuer 不是可信 AA |
| `UNKNOWN_KEY` | 401 | 公钥不在可信注册表 |
| `KEY_REVOKED` / `KEY_OUTSIDE_VALIDITY` / `WRONG_KEY_PURPOSE` / `KEY_SUBJECT_MISMATCH` | 401 | 公钥状态/用途/主体/时间窗不匹配 |
| `CAPABILITY_NOT_YET_VALID` / `CAPABILITY_EXPIRED` | 401 | Capability 时间窗错误 |
| `AUDIENCE_MISMATCH` | 401 | Capability/Holder Proof audience 不是当前 Broker |
| `REQUEST_BINDING_MISMATCH` | 401 | 请求字段与 Capability 不一致 |
| `REQUEST_HASH_MISMATCH` | 401 | 重新计算的 SM3 请求摘要不一致 |
| `CHALLENGE_MISMATCH` | 401 | Holder Proof Challenge 不等于预期 |
| `HOLDER_BINDING_MISMATCH` | 401 | Holder Proof 的 Capability/请求/Agent 绑定不一致 |
| `PROOF_NOT_YET_VALID` / `PROOF_EXPIRED` | 401 | Holder Proof 时间窗错误 |

## A：Receipt 复核

| 错误码 | 含义 |
|---|---|
| `BROKER_MISMATCH` | Receipt 的 `broker_id` 不是预期的 Broker |
| `RESULT_BINDING_MISMATCH` | `result_envelope` 的 SM3 与 `result_hash` 不符，或 `capability_id` / `request_hash` / `outcome` 与 Receipt 不一致 |

签名与公钥类复核失败沿用上表的 `INVALID_SIGNATURE`、`UNKNOWN_KEY` 等。

## B：Broker 执行阶段（`POST /v1/execute`）

| 错误码 | HTTP | 步骤 | 含义 |
|---|---:|---|---|
| `CANONICALIZATION_ERROR` / `SCHEMA_VALIDATION_FAILED` | 400 | schema | Execution Bundle 解析失败 |
| `INVALID_SIGNATURE` / `INVALID_SIGNATURE_ENCODING` / `SIGNATURE_KEY_MISMATCH` | 403 | capability_signature / holder_proof | Capability 或 Holder Proof 验签失败 |
| `UNTRUSTED_ISSUER` / `UNKNOWN_KEY` / `KEY_REVOKED` / `KEY_OUTSIDE_VALIDITY` / `WRONG_KEY_PURPOSE` / `KEY_SUBJECT_MISMATCH` | 403 | capability_signature / holder_proof | issuer 或公钥不可信 |
| `CAPABILITY_NOT_YET_VALID` / `CAPABILITY_EXPIRED` | 403 | capability_validity | Capability 时间窗错误 |
| `AUDIENCE_MISMATCH` | 403 | capability_validity / holder_proof | audience 不是本 Broker |
| `REQUEST_BINDING_MISMATCH` / `REQUEST_HASH_MISMATCH` | 403 | request_binding | 请求字段或 SM3 摘要与 Capability 不一致 |
| `HOLDER_BINDING_MISMATCH` / `PROOF_NOT_YET_VALID` / `PROOF_EXPIRED` | 403 | holder_proof | Holder Proof 绑定或时间窗错误 |
| `UNSUPPORTED_OPERATION` | 403 | execution_plan | 请求无法精确映射为受支持的上游调用 |
| `CHALLENGE_UNKNOWN` / `CHALLENGE_USED` / `CHALLENGE_EXPIRED` / `CHALLENGE_WRONG_AGENT` / `CHALLENGE_WRONG_AUDIENCE` | 403 | challenge | Broker Challenge 不存在 / 已用 / 过期 / 属于其他 Agent / 属于其他 Broker |
| `CREDENTIAL_NOT_FOUND` | 403 | atomic_consume | Credential 不存在 |
| `CREDENTIAL_INACTIVE` | 403 | atomic_consume | 执行时 Credential 不是 `ACTIVE` |
| `CREDENTIAL_EPOCH_MISMATCH` | 403 | atomic_consume | Capability 的 epoch 不等于 Broker 当前 epoch |
| `CAPABILITY_ALREADY_FAILED` | 403 | atomic_consume | 该 Capability 之前执行失败（含崩溃后启动恢复），不能再次使用 |
| `REPLAY_IN_PROGRESS` | 409 | atomic_consume | 同一 Capability 正在被另一个请求消费 |
| `IDEMPOTENCY_CONFLICT` | 409 | atomic_consume | 同一 Capability 携带了不同的请求 |
| `CAPABILITY_CLAIM_MISMATCH` | 409 | atomic_consume | 同一 Capability 携带了不同的 Credential ID / epoch / nonce |
| `CAPABILITY_NONCE_REUSED` | 409 | atomic_consume | 该 nonce 已属于另一个 Capability |
| `CREDENTIAL_UNAVAILABLE` | 403 | credential_decrypt | 消费后 Credential 已变化或无法解密；Capability → `FAILED` |
| `UPSTREAM_REJECTED` | 200 | upstream | 上游返回 3xx/4xx；Receipt `outcome=ERROR`，Capability → `CONSUMED` |
| `UPSTREAM_ERROR` | 502 | upstream | 上游不可达或 5xx；Capability → `FAILED` |
| `EXECUTION_DISABLED` | 503 | — | Broker 未配置可信 issuer / 公钥表 |
| `INTERNAL_ERROR` | 500 | — | 内部故障；拒绝仍然失败关闭。也记录在启动恢复的 Capability 上 |

## B：管理与查询接口

| 错误码 | HTTP | 含义 |
|---|---:|---|
| `BAD_REQUEST` | 400 | 请求体或参数非法 |
| `UNAUTHORIZED` | 401 | 缺少或错误的管理员令牌 |
| `NOT_FOUND` | 404 | Capability 从未被本 Broker 消费过 |
| `CREDENTIAL_NOT_FOUND` | 404 | Credential 不存在（执行阶段同一码返回 403） |
| `CONFLICT` | 409 | Credential 已存在 |
| `INVALID_STATE_TRANSITION` | 409 | 生命周期操作在当前状态下不允许（如对已销毁的 Credential 轮换） |
| `RESET_DISABLED` | 403 | 未开启 `BROKER_ENABLE_RESET` |

## 加载与配置错误（启动时失败关闭，不作为请求拒绝返回）

| 错误码 | 位置 | 含义 |
|---|---|---|
| `DUPLICATE_KEY_ID` | A / B 公钥表 | 公钥表中出现重复 `key_id`，整张表拒绝加载 |
| `INVALID_PUBLIC_KEY` / `INVALID_PRIVATE_KEY` | A | PEM 无法解析或不在 SM2 曲线上 |
| `INVALID_DOMAIN` | A | 签名域分离的 purpose 非 ASCII、为空或含 NUL（编程错误） |

## A 与 B 的对照

- **错误码是契约，HTTP 状态只是各接口的传输映射。** A 的参考验签接口（`/v1/capabilities/verify`）对签名/绑定失败返回 401；Broker 的 `/v1/execute` 对同一错误码返回 403。两者错误码相同，C 的 CSV 以错误码为准。
- **Challenge**：A 的参考校验器只比对“Holder Proof 中的 Challenge 是否等于调用方给定的值”，失败为 `CHALLENGE_MISMATCH`。Broker 自己签发和登记 Challenge，所以能细分为 `CHALLENGE_UNKNOWN` / `USED` / `EXPIRED` / `WRONG_AGENT` / `WRONG_AUDIENCE`。`CHALLENGE_MISMATCH` 不会出现在 Broker 的响应里。
- **`CREDENTIAL_INACTIVE`** 两边都用：A 在签发前由 Status 判定，B 在执行事务内判定，语义相同（Credential 不是 `ACTIVE`）。

## 生命周期边界

- A 的 `CREDENTIAL_STATUS_*` 是**签发前**的预检查，只缩短陈旧窗口；
- B 的 `CREDENTIAL_INACTIVE` / `CREDENTIAL_EPOCH_MISMATCH` 是**执行时**的最终线性化检查；
- 两者不能互相替代，C 的 CSV 应记录实际返回的错误码，而不是只记录 HTTP 状态。
