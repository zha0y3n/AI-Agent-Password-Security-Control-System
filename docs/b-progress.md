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
