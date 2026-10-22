# Broker 审计哈希链与签名检查点（字节格式）

> 供成员 C 独立验证。Go 参考实现：`credential-broker/internal/evidence/audit.go` 中的 `VerifyChain`。

## 1. 获取数据

| 接口 | 说明 |
|---|---|
| `GET /v1/audit?from=1&limit=1000` | 审计条目，`limit` 最大 1000，分页取完 |
| `GET /v1/audit/checkpoints` | 全部签名检查点 |
| `GET /v1/broker/public-key` | Broker 的两把 SM2 公钥。**检查点用 `checkpoint_key.public_key`**（未压缩 `04‖X‖Y` 十六进制，另有 `checkpoint_key.public_key_pem`）；顶层的 `public_key` / `public_key_pem` 是 Receipt 签名公钥，不签检查点 |
| `GET /v1/broker/key-registry` | 同一公钥，以 A 的 `KeyRegistryDocument` 格式发布（用途 `RECEIPT_SIGNING`） |
| `GET /v1/audit/verify` | Broker 用自己的参考实现复核整条链与全部检查点，返回 `valid`、`entries`、`checkpoints`、`head_hash` |
| `POST /v1/audit/checkpoints` | 管理员强制为当前链头生成检查点 |

条目格式：

```json
{"seq": 3, "entry": "{\"at\":1791797696,\"data\":{...},\"seq\":3,\"type\":\"credential.rotate\"}",
 "prev_hash": "<hex>", "hash": "<hex>"}
```

`entry` 字段是条目 `L_i` 的**原始字节**（UTF-8 JSON 文本），验证时直接按字符串字节使用，不要重新序列化。

`L_i` 是 `{"at","data","seq","type"}` 的 `ZTCANON-JSON-v1` 编码（与 A 的 `canonical_json` 相同：键按 code point 升序、无空白、无浮点）。因此 `canonical_json(json.loads(entry)) == entry` 对每条新条目成立，可以作为额外的格式检查。

## 2. 哈希链

```text
H_0 = 32 个 0x00 字节
H_i = SM3( H_{i-1} ‖ L_i )        -- 直接拼接，无分隔符
```

校验规则：

1. `seq` 从 1 开始连续递增（检测删除、重排）
2. `L_i` 中内嵌的 `seq` 等于记录的 `seq`
3. `prev_hash == H_{i-1}`
4. `hash == SM3(prev_hash ‖ entry)`

## 3. 签名检查点

```text
msg = "ACG-AUDIT-CHECKPOINT-v1"      (ASCII, 23 字节)
    ‖ uint64_be(seq)
    ‖ head_hash                       (32 字节，= H_seq)
    ‖ uint64_be(created_at)

signature = SM2-Sign(sk_CP, msg)      -- 含 Z 值预处理，UID = "1234567812345678"，ASN.1 DER 编码

sk_CP 是专用的检查点私钥（BROKER_CHECKPOINT_KEY_FILE），与 Receipt 签名私钥分开：
A 的公钥模型中 RECEIPT_SIGNING 只用于回执。
```

校验规则：

1. 签名用 `checkpoint_key.public_key` 验证通过
2. `seq` 不超过当前条目数（否则说明日志被**回滚或截断**）
3. `head_hash == H_seq`

`BROKER_CHECKPOINT_EVERY`（默认 100）条自动生成一个检查点；实验前后可调用 `POST /v1/audit/checkpoints` 固定链头。

> 已知限制：最后一个检查点之后的尾部条目若被截断，只能在下一个检查点时发现。

## 4. 事件类型

| type | 触发 | data 主要字段 |
|---|---|---|
| `credential.create` | 录入 / 重建 Credential | credential_id, provider, status, credential_epoch |
| `credential.rotate` / `.disable` / `.enable` / `.revoke` / `.compromise` / `.destroy` | 生命周期变更 | credential_id, from_status, to_status, from_epoch, credential_epoch |
| `capability.consume` | 赢得 Capability 唯一执行权 | cap_id, request_hash, credential_id, credential_epoch |
| `capability.complete` | 执行成功 | cap_id, result_hash |
| `capability.fail` | 执行失败 | cap_id, error_code |
| `execute.deny` | 请求被拒绝 | failed_step, code；Capability 验签通过时另有 cap_id, request_hash, receipt_id |
| `capability.recover` | 启动时把崩溃遗留的 `CONSUMING` 改为 `FAILED` | cap_id, error_code, reason |
| `keys.reload` | `SIGHUP` 成功重新加载 AA / Agent 公钥表 | trusted_keys |

审计内容**从不包含** Credential 明文或密文。

## 5. 编码变更说明

2026-10-21 之前的条目用 Go `encoding/json` 输出（字段顺序 `seq, at, type, data`，`<`、`>`、`&` 会转义为 `\u003c` 等）。哈希只覆盖原始字节，所以旧条目和新条目可以出现在同一条链里，复核方法不变；只有“重新规范化后字节相同”这项额外检查不适用于旧条目。
