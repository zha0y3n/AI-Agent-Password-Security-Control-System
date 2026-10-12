# 威胁模型

## 安全目标

- Agent 永不获得目标业务系统长期 Credential 明文。
- 未经可信任务授权的 Candidate Request 不会得到 AA Capability。
- Capability 任何签名覆盖字段被修改后验签失败。
- 窃取 Capability 的其他 Agent 因缺少正确 Holder 私钥而失败。
- 实际请求、Broker Audience、Credential epoch 或时间窗不一致时拒绝。
- B 完成后，同一 Capability 并发副作用数不超过 1，并留下可验证 Receipt。

## 攻击者能力

攻击者可控制用户输入、网页/RAG/文档、工具/MCP 返回、Agent/LLM 输出和 Candidate Request；可窃取/篡改/重放 Capability；可构造跨任务、跨服务、跨资源、错误参数和错误 audience；可在轮换/撤销/执行间制造竞态；可修改普通日志。

## 信任假设

- AA、Broker、Vault、可信状态存储和其私钥/主密钥未被完全攻破。
- 可信任务建立渠道正确识别用户意图；Agent 不能写该存储。
- Agent Holder 私钥不可直接导出；当前 demo 仅用文件模拟，生产建议独立 Holder Signer/HSM。
- 受保护 API 不允许 Agent 绕过 Broker 直接访问。
- B 使用可信当前 Credential 状态/epoch，并对 Challenge/Capability 原子消费。

## 非目标

不保证 LLM 不受 Prompt Injection、不保证用户不会误授权、不保证业务结果正确、不保证 Broker/Vault 完全失陷后的机密性，也不声称跨外部 API 与本地数据库具有严格 exactly-once 分布式事务。

## 信任边界

```text
不可信：用户/外部内容/LLM/Agent request
                  │
                  ▼
可信：AA task store + policy + SM2 signing
                  │ Signed Capability
                  ▼
半可信持有者：Agent/Holder Signer
                  │ request + capability + proof
                  ▼
可信：Broker state + Vault + protected API path
```

AA 的关键控制是“不对 Agent 自选请求直接签名”。B 的关键控制是“全部检查完成前不触碰 Credential”。C 必须以实际 Credential 访问和副作用计数验证，而不能只检查错误响应。

## 剩余风险

- 可信任务被错误创建或授权过宽；
- Agent Holder 私钥所在主机被完全控制；
- AA 与 Broker 对 canonical JSON、SM2 ID、时间或字段类型理解不同；
- Challenge 或 Capability 消费不是原子操作；
- Credential epoch 同步延迟；
- 外部 API 不支持幂等键导致故障重试重复副作用；
- 日志/检查点未进入独立可信存储。
