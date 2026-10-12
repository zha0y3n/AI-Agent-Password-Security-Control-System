# credential-broker（B 负责）

这里目前只保留 B 模块的工程入口和契约说明，没有实现 Broker/Vault 核心业务。

B 应尽快实现：

- Go HTTP 服务与 `shared/schemas/` 严格解码（拒绝未知/重复字段）；
- AA SM2 签名、Holder Proof、Task/Request/Audience/TTL 校验；
- Broker Challenge 的签发、短期存储和原子一次性消费；
- Credential 状态、epoch、轮换/撤销/销毁和 SM4-GCM Vault；
- Capability `ISSUED -> CONSUMING -> CONSUMED` 原子状态机；
- 幂等执行、受保护 Mock API、回执签名和审计链。

签名字节与 Go 建议调用见 `docs/crypto-protocol.md`，验收顺序见 `docs/a-b-interface.md`。禁止在此目录放真实 Credential。
