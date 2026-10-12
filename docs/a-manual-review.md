# 需要人工审核的 A 端设计

以下决定一旦进入 B/C 会形成协议兼容承诺，建议负责人逐项签字确认。

1. **授权来源**：AA 只从服务端 `TrustedTaskStore` 取上下文；当前固定策略要求 method/path/query/body 完全相等。是否需要可信 UI、审批人签名或策略版本号？
2. **Canonical JSON**：自定义 `ZTCANON-JSON-v1` 禁止 float，允许 Unicode 但不做 normalization。是否改用正式 RFC 8785/JCS 或 CBOR deterministic encoding？改动会破坏现有向量。
3. **SM2 签名语义**：签原始域分离消息，由 SM2-with-SM3 内部计算 `ZA || message`；SM2 ID 固定 `1234567812345678`；签名为 ASN.1 DER。请重点确认 Go 库调用不会预哈希或双重哈希。
4. **请求哈希覆盖范围**：当前包含 `request_id`、Agent/Task 和 Credential ID。确认 B 执行层不会重建/省略字段后再哈希。
5. **TTL/时钟**：Capability 最大 300 秒、示例策略 60 秒，Python verifier 容忍未来 `issued_at` 5 秒但过期边界严格为 `now >= expires_at`。确认比赛部署的时钟同步和 skew。
6. **Challenge**：格式为 16～32 字节小写 hex，生产由 Broker 生成并原子消费。需要确定 Challenge API、绑定会话、过期清理和失败重试。
7. **Credential Epoch 来源**：首轮 AA 从可信任务策略绑定 epoch=17；Broker 必须按执行时实时状态复核。需要确定 AA 是否查询 B 的 epoch、使用签名快照，还是只由 B 最终判定。
8. **一次性和幂等**：Capability 声明 `one_time=true`，但 A 不实现 B 的 CAS。请审核外部 API 幂等键、`CONSUMING` 崩溃恢复和撤销线性化点。
9. **回执结果摘要**：Receipt 字段已固定，但业务 `result_envelope` schema 未固定。B/C 联审前不要把 result hash 当作完整可验证业务语义。
10. **密钥生命周期**：注册模型支持 ACTIVE/REVOKED 和时间窗，但尚无轮换 API/证书链/HSM。生产 demo 前必须审核密钥托管和旧公钥保留窗口。
11. **密钥同机风险**：`init-demo` 为方便演示把 AA/Agent 私钥放同一 gitignored 目录；AA `serve` 不加载 Agent 私钥。正式部署必须进程/主机或 Holder Signer 隔离。
12. **“零接触”表述**：只能声称长期业务 Credential 对 Agent 零接触，不能声称 Agent 没有任何私钥。
