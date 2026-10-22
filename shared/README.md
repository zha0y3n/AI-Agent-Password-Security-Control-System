# shared：跨语言协议产物

本目录是 AA（Python）、Broker（Go）与评测模块共同遵循的协议事实源。修改签名字段、Canonical JSON、SM2 用户 ID、签名输入、DER/base64url 编码或错误语义时，必须由 AA 与 Broker 双方共同评审。

## Schemas

| 文件 | 权威模型 | 用途 |
|---|---|---|
| `agent-request.schema.json` | `agent_aa.models.AgentRequest` | Agent 提交的明确请求 |
| `task-context.schema.json` | `agent_aa.models.TaskContext` | AA 服务端可信任务上下文 |
| `signed-capability.schema.json` | `agent_aa.models.SignedCapability` | AA 签发的授权票据 |
| `holder-proof.schema.json` | `agent_aa.models.HolderProof` | Agent 持有者证明 |
| `execution-bundle.schema.json` | `agent_aa.models.ExecutionBundle` | Agent→Broker 的 request + capability + proof |
| `signed-receipt.schema.json` | `agent_aa.models.SignedReceipt` | Broker 执行回执 |
| `credential-status.schema.json` | `agent_aa.models.CredentialStatus` | Broker→AA 的非秘密 Credential 生命周期元数据 |
| `result-envelope.schema.json` | `agent_aa.models.ResultEnvelope` | Receipt 的 `result_hash` 所覆盖的执行结果 |

`credential-status.schema.json` 只包含 `credential_id`、`provider`、`status`、`credential_epoch`、`created_at`、`updated_at`。它不是 Agent 可提交的授权上下文，也不包含 Credential 明文或密文。AA 的 `BROKER_LIVE` 读取该元数据；Broker 执行事务内的 `ACTIVE + epoch` 原子检查仍是最终授权点。

## `result_envelope`

```text
result_hash = lowercase_hex(SM3(ZTCANON-JSON-v1(result_envelope)))
```

| 字段 | 取值 |
|---|---|
| `protocol_version` | `"1.0"` |
| `capability_id` / `request_hash` | 与 Receipt 中的同名字段相同 |
| `outcome` | `SUCCESS` / `DENIED` / `ERROR`，与 Receipt 的 `outcome` 相同 |
| `code` | 错误码（见 `docs/error-codes.md`）；只有 `SUCCESS` 为 `null` |
| `upstream_status` | 上游 HTTP 状态码（100～599）；未调用上游时为 `null`。`SUCCESS` 必须有，`DENIED` 必须没有 |
| `upstream_body` | 上游 JSON；不符合 ZTCANON-JSON-v1（如含浮点）时为原始文本字符串；未调用上游时为 `null` |

Receipt 签发规则：

| 场景 | outcome | code | Receipt |
|---|---|---|---|
| 上游 2xx | `SUCCESS` | `null` | 签发，Capability → `CONSUMED` |
| 上游 3xx/4xx | `ERROR` | `UPSTREAM_REJECTED` | 签发，Capability → `CONSUMED` |
| 上游不可达 / 5xx，或消费后 Credential 已变化 | `ERROR` | `UPSTREAM_ERROR` / `CREDENTIAL_UNAVAILABLE` | 签发，Capability → `FAILED` |
| Capability 验签通过后的任何拒绝 | `DENIED` | 拒绝码 | 签发，状态不变 |
| `schema` / `capability_signature` 阶段的拒绝 | — | — | **不签发**（字段可能是伪造的） |

- 幂等重放（同一 Capability、同一请求、新 Challenge）返回**字节相同**的 Receipt 与 `result_envelope`；
- 验证方先用 `ReceiptVerifier.verify_result()`（或等价步骤：验签 → 重算 `result_hash` → 比对 `capability_id` / `request_hash` / `outcome`），不一致返回 `RESULT_BINDING_MISMATCH`；
- 评测 CSV 中的 `error_code` 取自 `decision.code`，与 `result_envelope.code` 一致。

## Test vectors

`test-vectors/sm2-sm3-v1.json` 覆盖：

- Canonical JSON 与 SM3 已知答案；
- Capability、Holder Proof、Execution Receipt 三个签名域；
- SM2 公钥、DER 签名和测试私钥标量。

`test-vectors/result-envelope-v1.json` 覆盖五类 `result_envelope`（成功、上游 4xx、上游非规范 JSON、上游不可达、拒绝）：Broker 的输入、envelope、规范字节和 `result_hash`。Go（`credential-broker/internal/receipt/vector_test.go`）与 Python（`agent-aa/tests/test_result_envelope.py`）都逐字节核对。它不含签名，可确定性重新生成。

向量中的私钥仅用于互操作测试，绝不能用于部署。SM2 签名具有随机性：重新签名不要求 DER 字节相同，只要求双方互相验签成功。

只有权威模型或协议字节真正变化时才重新生成 Schema/向量：

```bash
.venv/bin/python scripts/generate-schemas.py
.venv/bin/python scripts/generate-test-vectors.py
.venv/bin/python scripts/generate-result-envelope-vectors.py
```

不要为了“刷新”而重生成向量；这会产生随机 SM2 签名差异和噪声 diff。

## 变更控制

- 修改 `ZTCANON-JSON-v1`、SM2 ID、域分离前缀、签名编码或错误语义：AA 与 Broker 联审；
- 修改 `result_envelope` 或 Receipt 返回方式：AA、Broker 与评测模块联审；
- 修改 Credential Status 字段：AA 与 Broker 联审，并同步 `docs/a-b-interface.md`；
- 新增协议版本时，必须保留旧版本验证窗口或明确不兼容。
