# Credential Broker

## 已完成

| 计划项 | 实现位置 | 说明 |
|---|---|---|
| 1.1 工程骨架 | `cmd/broker`、`internal/api`、`internal/config`、`internal/logging` | `/health`、配置校验、脱敏日志、优雅退出 |
| 1.2 国密封装 | `internal/crypto` | SM3 / SM4 国标向量；SM4-GCM；SM2 签名验签（DER，默认 UID） |
| 1.3 数据层 | `internal/repository` | SQLite（WAL + `BEGIN IMMEDIATE`），可重复迁移，事务封装 |
| 1.4 Vault | `internal/vault`、`internal/secret` | SM4-GCM，AAD 绑定 id / provider / epoch（长度前缀）；`Secret` 类型防打印 |
| 1.5 生命周期 | `internal/credential` | Create / Rotate / Disable / Enable / Revoke / Compromise / Destroy，每次 epoch++ |
| 1.6 Atomic Consume | `internal/capability` | ISSUED → CONSUMING → CONSUMED / FAILED，CAS + 同事务 Epoch 检查 |
| 1.7 幂等 | `internal/capability` | 同 cap + 同请求返回旧结果；不同请求拒绝 |
| 1.8 Mock 服务 | `internal/upstream`、`cmd/mock-upstream` | Mock Git / DB，需 Credential，副作用计数，下游幂等 |
| 1.9 审计链 | `internal/evidence` | SM3 哈希链 + SM2 签名检查点，`VerifyChain`；格式见 `docs/audit-chain.md` |
| 1.10 校验流水线 | `internal/verifier`、`internal/execution` | 有序步骤框架 + 执行器（拒绝路径不读 Credential、不调上游） |
| 1.11 Challenge | `internal/challenge` | CSPRNG，绑定 agent，TTL，单次使用 |
| 1.12 埋点 / 容器 | `internal/metrics`、`Dockerfile` | 各阶段 P50/P95/P99；distroless 非 root 镜像 |

## 阶段二（进行中）

| 计划项 | 实现位置 | 说明 |
|---|---|---|
| Go Canonical JSON | `internal/canonical` | `ZTCANON-JSON-v1` 严格解析 + 编码，四段 `canonical_hex` 向量逐字节一致 |
| 协议对象 / Request Hash | `internal/protocol` | 镜像 `agent_aa.models` 的约束与默认值；拒绝未知字段；SM3 请求摘要通过向量 |
| SM2 域分离验签 | `internal/protocol`、`internal/crypto` | `AACRED‖0‖purpose‖0‖v1‖0‖payload`，显式 UID，DER/base64url，PEM SPKI；Capability / Holder Proof / Receipt 三组向量 Go 验过，篡改版本全部失败 |
| 可信公钥表 | `internal/protocol/keys.go` | 直接读取 A 的 `public-keys.json` 格式；查找顺序与错误码同 `agent_aa.keys` |
| Challenge 格式 | `internal/challenge` | 改为 32 字节小写十六进制（符合 `HolderProofBody.challenge`），记录并校验 audience |
| 校验流水线 | `internal/verifier/steps.go` | schema → Capability 签名 → 时间/audience → 请求绑定与哈希 → Holder Proof → 执行计划 → Challenge 消费；之后由 Executor 在同一事务内检查 Credential 状态/Epoch 并 CAS |
| 请求映射 | `internal/verifier/plan.go` | AgentRequest 精确映射为 Mock Git/DB 调用，method/path/resource/body 不一致即拒绝 |
| 跨语言联调 | `make interop` | A 的 Python 代码签发 bundle，Go Broker 完整执行（Vault 解密 + Mock 上游），篡改与重放被拒 |

测试覆盖 23 类拒绝（每类断言停在预期步骤、未读取 Credential、未调用上游）、被拒请求不消耗 Challenge、原样重放、同 Capability 新 Challenge 幂等返回、20 路并发重放写操作副作用恰好一次。

### 尚未完成（等 A/B 对齐）

- `POST /v1/execute` 对外接口与 Receipt 签发：`result_envelope` 结构、Receipt 返回方式未定。
- Credential Epoch 来源：A 的可信任务库写死 17，Broker 新建 Credential 从 1 开始。联调测试暂时通过轮换把测试 Credential 推到 17。
- Broker 公钥目前以 `04‖X‖Y` 十六进制公布；A 的 `ReceiptVerifier` 需要 PEM SPKI 记录，签发 Receipt 前一并对齐。

## HTTP 接口（阶段一）

| 方法 | 路径 | 权限 |
|---|---|---|
| GET | `/health` | 公开 |
| GET | `/v1/broker/public-key` | 公开 |
| POST | `/v1/challenge` | 公开 |
| GET | `/v1/credentials/{id}/status` | 公开（仅元数据，供 AA 获取 Epoch） |
| POST | `/v1/credentials` | 管理员 |
| POST | `/v1/credentials/{id}/rotate` | 管理员 |
| POST | `/v1/credentials/{id}/{disable\|enable\|revoke\|compromise\|destroy}` | 管理员 |
| GET | `/v1/audit`、`/v1/audit/checkpoints` | 公开 |
| POST | `/v1/audit/checkpoints` | 管理员 |
| GET | `/v1/metrics` | 公开 |
| POST | `/v1/metrics/reset` | 管理员 |

Mock 服务（默认 `:9090`）：`/git/repos/{repo}/files/{path}`、`/db/{db}/query|update`、`GET /stats`、`POST /reset`。
