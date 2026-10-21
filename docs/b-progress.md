# Credential Broker

更新时间：2026-10-22（Asia/Shanghai）。完整度：**92%**。

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

## 阶段二：接入 A 的协议（完成）

| 计划项 | 实现位置 | 说明 |
|---|---|---|
| Go Canonical JSON | `internal/canonical` | `ZTCANON-JSON-v1` 严格解析 + 编码，四段 `canonical_hex` 向量逐字节一致 |
| 协议对象 / Request Hash | `internal/protocol` | 镜像 `agent_aa.models` 的约束与默认值；拒绝未知字段；SM3 请求摘要通过向量 |
| SM2 域分离验签 | `internal/protocol`、`internal/crypto` | `AACRED‖0‖purpose‖0‖v1‖0‖payload`，显式 UID，DER/base64url，PEM SPKI；三组向量 Go 验过，篡改版本全部失败 |
| 可信公钥表 | `internal/protocol/keys.go` | 直接读取 A 的 `public-keys.json`；查找顺序与错误码同 `agent_aa.keys` |
| Challenge 格式 | `internal/challenge` | 32 字节小写十六进制，记录并校验 audience |
| 校验流水线 | `internal/verifier` | schema → Capability 签名 → 时间/audience → 请求绑定与哈希 → Holder Proof → 执行计划 → Challenge 消费 |
| 执行接口 | `internal/api/execute.go` | `POST /v1/execute`：Execution Bundle → 校验 → 原子消费 → Vault → Mock → Receipt → 审计 |
| Receipt 签发 | `internal/receipt` | SUCCESS / ERROR / DENIED 三类回执，A 的 `ReceiptVerifier` 验过（`make interop`）；幂等重放返回同一张 |
| Broker 公钥记录 | `GET /v1/broker/key-registry` | 以 A 的 `KeyRegistryDocument` 格式公布 PEM SPKI 公钥（解决之前 `04‖X‖Y` 与 PEM 不一致的问题） |
| 错误码 / HTTP 状态 | `internal/errcode` | 协议码沿用 A；B 扩展生命周期 / 重放 / 上游码；映射表见 `credential-broker/README.md` |

## 阶段三：A + B 联调（B 侧完成，待生命周期真实联调）

`scripts/e2e-demo.py` 通过真实 HTTP 跑通 Agent → AA → Challenge → Holder Proof → Broker → Vault → Mock → Receipt → Audit，覆盖重放、幂等、篡改请求、篡改 Capability、被窃取 Capability、伪造 Challenge、提示注入、旧 Epoch，并核对上游调用次数和审计链。

A 已实现可选的 `BROKER_LIVE`：签发前读取 `GET /v1/credentials/{id}/status` 的当前 `ACTIVE` epoch。真实 TLS/mTLS、轮换、撤销和撤销竞态联调仍待完成；B 执行事务内的 `ACTIVE + epoch` 原子检查仍是最终线性化点。

## 阶段四：面向 C 的支撑（完成，待 C 确认）

Capability 状态查询、审计复核接口、状态重置（`BROKER_ENABLE_RESET`）、`scripts/seed.sh`（含批量 Credential）与 `scripts/reset.sh`，以及 `deploy/docker-compose.yml`（AA + Broker + Mock + 可选 Dashboard + e2e / reset 任务）。

### 尚待联审

- `result_envelope` 结构与 Receipt 返回方式（B 的提案见 `credential-broker/README.md`），需写入 `shared/`。
- 统一错误码表：A 的 `CREDENTIAL_STATUS_*` 与 B 的 `CREDENTIAL_EPOCH_MISMATCH` / `CREDENTIAL_INACTIVE` 尚未合并成一张表。
- A 的 `BROKER_LIVE` 已实现，待真实 B 的 TLS/mTLS 生命周期联调；默认 `STATIC_DEMO` 仍把 `github-prod` 对齐到 17。

## 阶段五：竞赛化（文档完成）

| 文档 | 内容 |
|---|---|
| [`credential-broker/docs/architecture.md`](../credential-broker/docs/architecture.md) | Broker 架构、校验流水线、Atomic Consume 语义（为什么不是严格 exactly-once）、Vault 设计、审计链、部署与密钥配置 |
| [`credential-broker/docs/security-mapping.md`](../credential-broker/docs/security-mapping.md) | 威胁 → 拦截步骤 → 拒绝码 → 测试 / 演示 |
| [`credential-broker/docs/defense.md`](../credential-broker/docs/defense.md) | 计划中的六个答辩问题、常见追问、演示流程 |

之后只修 Bug，不改协议。可选改进（崩溃恢复、公钥热加载、审计条目改用 ZTCANON）见 `architecture.md` §11。

## HTTP 接口

完整接口表、`/v1/execute` 响应与错误码见 [credential-broker/README.md](../credential-broker/README.md#http-接口)。
