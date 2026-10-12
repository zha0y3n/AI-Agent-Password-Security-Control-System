# Shared protocol artifacts

- `schemas/`：由 A 的 Pydantic 权威模型生成的 Draft 2020-12 JSON Schema。
- `test-vectors/sm2-sm3-v1.json`：Canonical JSON、SM3，以及 Capability、Holder Proof、Receipt 三个签名域的 SM2 公钥/签名和测试私钥标量。

向量中的私钥仅用于互操作测试，绝不能用于部署。修改签名字段或编码后，A/B 必须共同升级 `protocol_version` 或完成兼容性评审。
