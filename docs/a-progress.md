# A 模块第一轮进度

更新时间：2026-10-14（Asia/Shanghai）。

## 《111》周期对照

| 周期 | A 端状态 | 证据 |
|---|---|---|
| 1 | 已完成 | Monorepo、严格 AgentRequest/TaskContext/Capability、Canonical JSON |
| 2 | 已完成 | 铜锁 SM2/SM3、`issue_capability()`、Agent 调用/CLI/FastAPI |
| 3 | 已完成 | Agent→AA→Capability→HolderProof、实际请求 SM3 绑定 |
| 4 | 已完成（A 范围） | Audience/Broker、Credential ID/Epoch、TTL/nonce/request 绑定 |
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
- FastAPI、CLI、开发运行目录、Schema 和跨语言向量。

## 测试结果

本次非法 DER 修复回归：`41 passed`。`/v1/capabilities/verify` 对非法 DER 返回 401 `INVALID_SIGNATURE`，不再返回 500。

最近一次本机运行：`39 passed`。覆盖 Canonical JSON、SM3 已知答案、SM2 正常/篡改、正常签发、错误资源/Body/Task、布尔值与整数语义区分、TTL、票据/epoch 篡改、过期、跨任务/服务/资源/操作/路径、RequestHash、Audience、Wrong Holder、Challenge、Proof 过期、Receipt 篡改/验签 API、API 正常/拒绝/重复字段，以及 Capability/Holder Proof/Receipt 三类共享向量。本机 OpenSSL 3.0.13 也用显式 SM2 ID 成功验证了这三类铜锁签名。

未执行/未完成：Go 端向量验签、B/C 集成、Credential lifecycle、old epoch 实时拒绝、撤销、replay/并发 CAS、Vault、真实业务副作用、性能、提示注入、Dashboard 和审计链。这些不能由 A 的 reference verifier 替代。

环境说明：当前工作区位于 WSL 的 `/mnt/e` 挂载盘，运行时对私钥执行 `chmod 0600` 后仍报告 `0777`。代码现会显式告警；本机生成的 `.runtime/` 仅用于演示且已 gitignore，不能作为生产密钥存储。
