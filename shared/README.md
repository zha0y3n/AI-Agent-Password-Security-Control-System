# Shared protocol artifacts

本目录是 A/B/C 的跨语言协议事实源。修改签名字段、Canonical JSON、SM2 用户 ID、签名输入、DER/base64url 编码或错误语义时，必须由 A 和 B 共同评审。

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

`credential-status.schema.json` 只包含 `credential_id`、`provider`、`status`、`credential_epoch`、`created_at`、`updated_at`。它不是 Agent 可提交的授权上下文，也不包含 Credential 明文或密文。A 的 `BROKER_LIVE` 读取该元数据；Broker 执行事务内的 `ACTIVE + epoch` 原子检查仍是最终授权点。

## 尚未固化的协议

`result_envelope` 仍是 B 的提案：

```text
result_hash = SM3(ZTCANON-JSON-v1(result_envelope))
```

在 A/B/C 联审并写入 `shared/schemas/` 之前，不要把任意业务 JSON 当作跨语言稳定的 Receipt 语义。需要确认：

- 成功、业务错误、授权拒绝分别是否签发 Receipt；
- 幂等重放是否返回字节相同的 Receipt 和 envelope；
- 哪些早期拒绝没有 Receipt；
- `result_hash` 与 Receipt 的绑定、错误码与 C CSV 字段映射。

## Test vectors

`test-vectors/sm2-sm3-v1.json` 覆盖：

- Canonical JSON 与 SM3 已知答案；
- Capability、Holder Proof、Execution Receipt 三个签名域；
- SM2 公钥、DER 签名和测试私钥标量。

向量中的私钥仅用于互操作测试，绝不能用于部署。SM2 签名具有随机性：重新签名不要求 DER 字节相同，只要求双方互相验签成功。

只有权威模型或协议字节真正变化时才重新生成 Schema/向量：

```bash
.venv/bin/python scripts/generate-schemas.py
.venv/bin/python scripts/generate-test-vectors.py
```

不要为了“刷新”而重生成向量；这会产生随机 SM2 签名差异和噪声 diff。

## 变更控制

- 修改 `ZTCANON-JSON-v1`、SM2 ID、域分离前缀、签名编码或错误语义：A+B 联审；
- 修改 `result_envelope` 或 Receipt 返回方式：A+B+C 联审；
- 修改 Credential Status 字段：A+B 联审，并同步 `docs/a-b-interface.md`；
- 新增协议版本时，必须保留旧版本验证窗口或明确不兼容。
