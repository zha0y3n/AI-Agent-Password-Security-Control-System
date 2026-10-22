# A 模块第一轮进度

更新时间：2026-10-22（Asia/Shanghai）。完整度：**95%**（A 范围实现完成；真实 A+B 生命周期联调待完成）。

## 《111》周期对照

| 周期 | A 端状态 | 证据 |
|---|---|---|
| 1 | 已完成 | Monorepo、严格 AgentRequest/TaskContext/Capability、Canonical JSON |
| 2 | 已完成 | 铜锁 SM2/SM3、`issue_capability()`、Agent 调用/CLI/FastAPI |
| 3 | 已完成 | Agent→AA→Capability→HolderProof、实际请求 SM3 绑定 |
| 4 | 已完成（A 范围） | Audience/Broker、Credential ID/Epoch、TTL/nonce/request 绑定；可选 Broker 实时 epoch/status 解析器 |
| 5 | 已完成（A 范围） | 字节级协议固定、Schema、Python/Go 测试向量、失败关闭 |
| 6 | 已完成（A 范围） | ExecutionReceipt 结构、签名/验签参考实现与规范 |

结论：A 的专属交付达到第 6 周期。系统总体不等于《111》的 82%，因为 B 的 Vault/lifecycle/原子消费/真实执行/审计和 C 的系统实验/Dashboard 尚未实现。

## 已实现

- 固定任务 DeterministicAgent，不依赖大模型 API；
- Pydantic 严格模型和 unknown-field 拒绝；
- 重复 JSON key、float/NaN/Infinity/int64 越界拒绝；
- `ZTCANON-JSON-v1`；
- 铜锁 `tongsuopy` SM3 与 SM2-with-SM3；
- Agent/Issuer/Broker key ID、subject、purpose、状态和有效期注册模型；
- AA 服务端可信 TaskContext 精确匹配策略；
- Capability 五类核心绑定与完整签名；
- Holder Proof exact Capability hash + request + audience + challenge 绑定；
- ExecutionReceipt 数据结构、Broker 参考签名和 A 端验签；
- `BrokerCredentialStatusResolver`：仅在精确可信任务匹配后查询 Broker 公开元数据，将实时 ACTIVE Credential epoch 签入 Capability；查询/响应/状态任何异常均拒绝签发；
- FastAPI、CLI、开发运行目录、Schema 和跨语言向量。

## 测试结果

本次 P0 硬化后：`71 passed`。新增用例覆盖：真实本地 HTTP Status（重定向、超过 16 KiB、超时、坏状态行、截断响应、非 200、ID 不一致、非 ACTIVE）、`BROKER_LIVE` 经 `/v1/capabilities/issue` 的成功路径、`STATIC_DEMO` 不查询 Broker、TTL 拒绝先于查询、启动时只要求活跃任务 audience、AA 请求体 1 MiB 上限，以及深层嵌套 JSON 返回 400 而非 500。`/v1/capabilities/verify` 对非法 DER 返回 401 `INVALID_SIGNATURE`，不再返回 500。

最近一次本机运行：`71 passed`。覆盖 Canonical JSON、SM3 已知答案、SM2 正常/篡改、正常签发、错误资源/Body/Task、布尔值与整数语义区分、TTL、票据/epoch 篡改、过期、跨任务/服务/资源/操作/路径、RequestHash、Audience、Wrong Holder、Challenge、Proof 过期、Receipt 篡改/验签 API、API 正常/拒绝/重复字段、Broker 实时 epoch/status 失败关闭、真实 HTTP Status、请求体/深递归保护，以及 Capability/Holder Proof/Receipt 三类共享向量。本机 OpenSSL 3.0.13 也用显式 SM2 ID 成功验证了这三类铜锁签名。

2026-10-21（B 协助修改，待 A 复核）：Status 查询支持部署 CA 与客户端证书（`broker_status_ca_file`、`broker_status_client_cert_file`、`broker_status_client_key_file`），`79 passed`。`scripts/e2e-lifecycle.py` 已对真实 B 进程跑通，HTTP 与 HTTPS 各 13/13；B 开启 mTLS 时，配置客户端证书的 AA 能读到实时 epoch，未配置的按预期返回 `CREDENTIAL_STATUS_UNAVAILABLE`。撤销竞态与伪造 Status 场景仍未在真实联调中覆盖。B/C 的 Go 向量验签、Broker 执行时原子 lifecycle 检查、Vault、replay/并发 CAS、真实业务副作用、性能、提示注入、Dashboard 和审计链由 B/C 负责，不能由 A 的 reference verifier 或模拟 Status 响应替代。

环境说明：当前工作区位于 WSL 的 `/mnt/e` 挂载盘，运行时对私钥执行 `chmod 0600` 后仍报告 `0777`。代码现会显式告警；本机生成的 `.runtime/` 仅用于演示且已 gitignore，不能作为生产密钥存储。
