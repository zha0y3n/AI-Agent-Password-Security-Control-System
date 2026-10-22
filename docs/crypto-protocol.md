# 密码协议规范（v1.0）

本文是 Python/Go 互操作的字节级约定。若实现与本文冲突，必须拒绝并联审，不能静默换算法或猜测编码。

## 1. Canonical JSON

协议名：`ZTCANON-JSON-v1`。

- UTF-8，无 BOM；对象 key 按 Unicode code point 顺序升序（合法 UTF-8 上等价于按 UTF-8 字节排序）。
- 无空白；分隔符固定为 `,` 和 `:`；字符串按 JSON 转义，输出非 ASCII 字符本身。
- 允许 `null`、布尔值、字符串、数组、对象和有符号 64 位整数。
- 禁止 float、NaN、Infinity、重复 key、非法 Unicode、超出 int64 的整数和未知模型字段。
- 数组顺序有意义；不做 Unicode normalization。
- 所有签名结构包含其全部字段，`null` 不得擅自省略。

Python 权威函数为 `agent_aa.canonical.canonical_json()`；Go 必须实现相同 profile，不能直接依赖 `encoding/json` 对任意 `map` 的默认行为作为协议定义。

## 2. SM3 请求摘要

```text
request_bytes = ZTCANON-JSON-v1(AgentRequest)
request_hash  = lowercase_hex(SM3(request_bytes))
```

`request_hash` 是 64 个小写十六进制字符。它包含请求 ID、Agent/Key、Task、Service、Resource、Operation、HTTP method/path/query/body 和 Credential ID。

## 3. SM2 签名

### 3.1 域分离输入

```text
message = ASCII("AACRED") || 0x00
        || ASCII(purpose) || 0x00
        || ASCII("v1") || 0x00
        || canonical_payload
```

`purpose` 仅允许以下值：

| 对象 | purpose |
|---|---|
| CapabilityBody | `CAPABILITY` |
| HolderProofBody | `HOLDER_PROOF` |
| ExecutionReceipt | `EXECUTION_RECEIPT` |

### 3.2 算法和编码

- 算法：标准 SM2-with-SM3，对上述原始 `message` 签名。
- SM2 User ID：ASCII `1234567812345678`（16 bytes），Go 应显式传入，不能依赖库默认值。
- Python：`private_key.sign(message, ec.ECDSA(hashes.SM3()))`。
- 签名：ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)`，传输时 base64url、无 `=` padding。
- 公钥：PEM SubjectPublicKeyInfo；测试向量额外给出 `04 || X || Y` 未压缩点。

不要先对域分离消息做一次 SM3 再调用 SM2-with-SM3。后者会在 SM2 的 `ZA || message` 语义下内部散列，预哈希后再交给它会造成双重哈希和 Python/Go 不兼容。

Go 使用 `github.com/emmansun/gmsm/sm2` 时，对原始 message 的参考验签形态为：

```go
ok := sm2.VerifyASN1WithSM2(pub, []byte("1234567812345678"), message, signatureDER)
```

公钥 SPKI 可用同一项目的 `smx509.ParsePKIXPublicKey` 解析。B 必须用 `shared/test-vectors/sm2-sm3-v1.json` 先完成互操作测试。

## 4. Capability 签名覆盖范围

`SignedCapability.signature` 只签 `SignedCapability.body` 的完整 canonical bytes；signature 元数据不自签。验证器必须先要求元数据精确等于本协议，再按 body 中 `issuer_key_id` 查可信公钥。

Body 覆盖：协议版本、Capability ID、Issuer/Key、Audience、Agent/Key、Task、Service、Resource、Operation、RequestHash、Credential ID/Epoch、issued/expires/TTL、Nonce 和 `one_time=true`。

### 4.1 Credential Epoch 的签发来源

CapabilityBody 的 `credential_epoch` 是签名覆盖字段，不能由 Agent 提供或在签名后改写。AA 的可信任务只决定允许使用哪个 Credential 与哪个 Broker audience。部署启用实时生命周期联动时，AA 在完成该可信任务的精确匹配后，从该 audience 的受保护 Broker Status 端点获得当前 `ACTIVE` Credential epoch，再将其签入 Capability。查询失败或返回非 ACTIVE 状态必须拒绝签发。

该预检查不替代 Broker 执行时与 Capability 消费同一事务中的 `ACTIVE + epoch` 原子校验；后者是轮换/撤销竞态的最终线性化点。Status 端点的固定响应字段与传输身份要求见 `docs/a-b-interface.md`。

## 5. Holder Proof

Broker 先生成不可预测 Challenge，并在可信状态存储中记录其 audience、过期时间和未消费状态。Agent 对完整 `HolderProofBody` 签名。Body 同时绑定：

- `capability_id`；
- `capability_hash = SM3(CanonicalJSON(SignedCapability))`；
- Agent/Key；
- Audience；
- 实际 `request_hash`；
- Broker Challenge；
- proof issued/expires。

B 验签成功后仍必须原子消费 Challenge。仅比较 Challenge 字符串并不构成防重放。

## 6. Execution Receipt

生产回执由 B 签发，A 只提供结构与参考验签。回执绑定 Broker/Key、Capability、RequestHash、Credential ID/Epoch、ResultHash、Outcome 和执行时间。结果摘要为：

```text
result_hash = lowercase_hex(SM3(ZTCANON-JSON-v1(result_envelope)))
```

`result_envelope` 的结构见 `shared/schemas/result-envelope.schema.json`（权威模型 `agent_aa.models.ResultEnvelope`），字段、Receipt 签发规则与幂等重放语义见 `shared/README.md`，跨语言向量见 `shared/test-vectors/result-envelope-v1.json`。验证方用 `ReceiptVerifier.verify_result()` 同时核对签名与结果绑定。

## 7. 测试向量

`shared/test-vectors/sm2-sm3-v1.json` 包含请求 canonical bytes、SM3、Capability canonical bytes、完整签名 message、DER 签名、公钥和明确标注的测试私钥标量。SM2 签名具有随机性：重新签名不要求 DER 字节相同，只要求双方互相验签成功。
