# Credential Broker（B）

Broker 是系统里唯一的可信执行点。Agent 提交 **Execution Bundle**（AgentRequest + AA 签发的 Capability + Agent 的 Holder Proof）。Broker 逐项校验通过后，原子地消费 Capability，从 Vault 解密长期 Credential 调用受保护服务，最后签发 **Execution Receipt**。Agent 从头到尾拿不到 Credential。

Go 实现，国密原语来自 [`emmansun/gmsm`](https://github.com/emmansun/gmsm)，没有自研 SM2/SM3/SM4。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 设计说明：模块边界、执行时序、校验流水线顺序的理由、Atomic Consume 与线性化点、为什么不是严格 exactly-once、Vault 与 Epoch、Credential 明文出现的位置、回执、审计、密钥配置、已知限制 |
| [docs/security-mapping.md](docs/security-mapping.md) | 威胁与防御对照：每类攻击被哪一步拦下、返回什么码、由哪个测试或演示证明 |
| [docs/defense.md](docs/defense.md) | 答辩材料：六个必答题、常见追问、5 分钟演示流程 |
| [../docs/audit-chain.md](../docs/audit-chain.md) | 审计哈希链与检查点的字节格式（供 C 独立验证） |

## 完成度

| 阶段 | 内容 | 状态 |
|---|---|---|
| 一：基础设施 | 国密封装、SQLite、SM4-GCM Vault、Credential 生命周期与 Epoch、原子消费、幂等、Mock 上游、审计哈希链、Challenge、埋点、Docker | 完成 |
| 二：接入 A 的协议 | `ZTCANON-JSON-v1`、Request Hash、SM2 域分离验签（三组共享向量）、可信公钥表、校验流水线、`POST /v1/execute`、Receipt 签发（A 的 `ReceiptVerifier` 验过）、错误码与 HTTP 状态 | 完成；`result_envelope` 已固化进 `shared/` |
| 三：A + B 联调 | 真实 HTTP 全链路：Agent → AA → Challenge → Holder Proof → Broker → Vault → Mock → Receipt → Audit；`e2e-demo.py` 的 7 类攻击样例全部按预期拒绝或幂等处理；`e2e-lifecycle.py` 的生命周期联调 25/25 | 完成 |
| 四：面向 C 的支撑 | 副作用计数、Capability 状态查询、审计导出 / 复核、Broker 公钥记录、Metrics、状态重置、种子数据与批量 Credential、docker compose | 完成；接口是否够用待 C 确认 |
| 五：竞赛化 | 设计说明、威胁与防御对照、答辩材料（见上方“文档”） | 文档完成；之后只修 Bug，不改协议 |

**B 约 98%。** 剩下的是生产化项目：传输层改用国密 TLCP、真实上游的网络隔离、Vault 主密钥与管理令牌托管、多实例部署（目前单机 SQLite）。

2026-10-21 补齐：

- **A+B 生命周期真实联调**：A 的 `scripts/e2e-lifecycle.py` 对真实 Broker + Mock 进程 25/25（HTTP；HTTPS + Broker↔Mock mTLS 同样通过）。覆盖：签发与执行之间轮换；伪造 Status（未来 epoch、过期 epoch、撤销后仍称 ACTIVE）在执行时被拒；撤销后 AA 拒绝签发；Status 不可用；撤销与执行并发竞态 50 轮（35 轮先执行、15 轮先撤销），按审计链顺序核对全部可线性化。
- **`result_envelope` 固化**：见下方“Execution Receipt”。
- **统一错误码表**：[`docs/error-codes.md`](../docs/error-codes.md)，`internal/errcode/errcode_test.go` 守护。
- **崩溃恢复**：启动时（开始监听之前）把停在 `CONSUMING` 的 Capability 改为 `FAILED`（`error_code=INTERNAL_ERROR`，审计事件 `capability.recover`），不重试。
- **公钥**：`kill -HUP <broker>` 热加载 AA / Agent 公钥表（审计事件 `keys.reload`）；`BROKER_RETIRED_KEYS` 轮换 Broker Receipt 公钥并可标记 `REVOKED`。
- **传输**：Broker HTTPS / mTLS；Broker↔Mock mTLS（Credential 泄露也无法绕过 Broker 直接调用 Mock）。
- **审计条目**：`ZTCANON-JSON-v1` 编码，旧条目仍可复核。
- **DENIED 回执**：实测开销不到请求延迟的 1%，保持始终签发。

最近一次验证（2026-10-21）：

- `go vet`、`gofmt` 无问题，`go test -race ./...` 全部通过。
- `make interop` 通过：A 的 `ReceiptVerifier.verify_result()` 接受 Go 签发的回执与 `result_envelope`，篡改后的副本被拒绝。
- 用重新构建的镜像在 compose 里跑 `e2e`，14 项检查全部通过；AA、Broker、Mock 的日志中查不到 Credential、管理员令牌或 Vault 主密钥。
- C 的 7 类实验在干净副本上复现 110/110（`evaluation-dashboard/results/reproductions/2026-10-21/`）。

## 快速开始

### Docker Compose（推荐）

一条命令拉起 AA + Broker + Mock 上游，并自动录入种子 Credential。需要 Docker Compose v2。

```bash
cd credential-broker/deploy
sh gen-env.sh                     # 生成 .env：随机 Vault 主密钥、管理令牌、Mock Credential（已 gitignore）
docker compose up -d --build      # AA :8000、Broker :8080、Mock :9090，均只绑定 127.0.0.1
docker compose run --rm e2e       # 全链路联调 + 攻击样例
docker compose run --rm reset     # 两轮实验之间：清空 Broker / Mock 状态并重新 seed
docker compose --profile dashboard up -d dashboard   # 可选：C 的 Dashboard :8501
docker compose down -v            # 停止并删除全部卷（含生成的私钥）
```

密钥分布：`aa-init` 在 `aa-runtime` 卷里生成 AA 与 Agent 的私钥，只有 `aa` 和 `e2e` 挂载这个卷。公钥表另外复制到 `trust` 卷，Broker 以只读方式挂载，看不到 AA 或 Agent 的私钥。

### 本地运行

```bash
# 仓库根目录：安装 A，并生成 A 的开发运行时（.runtime/，含测试私钥，已 gitignore）
bash scripts/bootstrap.sh
.venv/bin/agent-aa init-demo --directory .runtime
bash scripts/run-a.sh &                                   # AA :8000

cd credential-broker
cp .env.example .env    # 填 BROKER_VAULT_KEY、BROKER_ADMIN_TOKEN、MOCK_GIT_TOKEN、MOCK_DB_TOKEN；实验环境可设 BROKER_ENABLE_RESET=1
set -a; . ./.env; set +a
make run-mock &                                           # Mock :9090
make run &                                                # Broker :8080
sh scripts/seed.sh                                        # 录入 github-prod（epoch 17）与 db-prod
../.venv/bin/python scripts/e2e-demo.py                   # 全链路联调
```

`e2e-demo.py` 扮演 Agent，期望输出：

```text
1. 正常执行：Agent -> AA -> Broker -> Mock Git
  [PASS] Broker 执行成功  (HTTP 200 None)
  [PASS] A 的 ReceiptVerifier 复核回执，result_hash 与 envelope 一致
  ...
2. 攻击样例
  [PASS] 原样重放整个 bundle  (HTTP 403 CHALLENGE_USED)
  [PASS] 同一 Capability + 新 Challenge：幂等返回同一回执，不再调用上游  (HTTP 200)
  [PASS] 篡改请求路径（恶意 Agent 自签持有证明）  (HTTP 403 REQUEST_HASH_MISMATCH)
  [PASS] 篡改 Capability（越权为 write_file）  (HTTP 403 INVALID_SIGNATURE)
  [PASS] 被窃取的 Capability（攻击者私钥签持有证明）  (HTTP 403 INVALID_SIGNATURE)
  [PASS] 伪造 Challenge（非 Broker 签发）  (HTTP 403 CHALLENGE_UNKNOWN)
  [PASS] 提示注入：Agent 请求任务外资源，AA 拒绝签发  (HTTP 403 REQUEST_NOT_AUTHORIZED)
3. 证据
  [PASS] 上游只被调用一次（所有攻击都在 Credential 读取前被拒绝）  (git calls +1)
  [PASS] 上游没有收到错误 Credential
  [PASS] 审计哈希链与检查点复核通过  (27 entries)
```

## 执行流程

```text
Agent ── POST /v1/challenge ──────────────────────────▶ Broker  记录 (challenge, agent, audience, 过期, 未用)
Agent ── POST /v1/execute  {request, capability, holder_proof}
           │
           ▼  校验流水线（internal/verifier，任一步拒绝即停止）
           1 schema                严格 ZTCANON-JSON-v1 + A 的 schema，拒绝未知字段 / 浮点 / 重复 key
           2 capability_signature  可信 issuer、issuer 公钥（用途 / 主体 / 有效期 / 状态）、SM2 验签
           3 capability_validity   issued_at / expires_at（±5s 时钟偏差）、audience = 本 Broker
           4 request_binding       Agent/Task/Service/Resource/Operation/Credential ID 逐项一致，重算 SM3 请求摘要
           5 holder_proof          Agent 公钥、SM2 验签、capability_hash、request_hash、audience、时间窗
           6 execution_plan        AgentRequest 精确映射为上游调用，含糊或多余即拒绝
           7 challenge             原子消费 Broker Challenge（前 6 步都是纯计算，被拒请求不浪费 Challenge）
           │
           ▼  internal/execution
           atomic_consume          同一写事务内：Credential 状态 = ACTIVE 且 epoch 相等 → Capability CAS 到 CONSUMING
           credential_decrypt      Vault SM4-GCM 解密（AAD 绑定 id / provider / epoch）—— 明文只在这里出现
           upstream                携带 Credential 调用 Mock，X-Idempotency-Key = capability_id；调用后清零明文
           receipt_sign            签发 Receipt；结果 + Receipt 落库为 CONSUMED，之后幂等重放返回同一张
```

任何拒绝都发生在读取 Credential 之前。测试逐条断言了 23 类拒绝：每一类都停在预期步骤，没有读取 Credential，也没有调用上游。

## HTTP 接口

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/health` | 公开 | 健康检查 |
| GET | `/v1/broker/public-key` | 公开 | Receipt 签名公钥（`public_key` 为 04‖X‖Y hex、`public_key_pem`、`key_record`），以及审计检查点公钥 `checkpoint_key` |
| GET | `/v1/broker/key-registry` | 公开 | A 的 `KeyRegistryDocument` 格式，可直接交给 `agent_aa.keys.KeyRegistry` 验 Receipt |
| POST | `/v1/challenge` | 公开 | `{"agent_id"}` → `{challenge, agent_id, audience, expires_at}` |
| POST | `/v1/execute` | 公开 | 请求体为 Execution Bundle，见下文 |
| GET | `/v1/capabilities/{id}` | 管理员 | Capability 消费状态：`ISSUED / CONSUMING / CONSUMED / FAILED`、`error_code` |
| GET | `/v1/credentials/{id}/status` | 公开 | Credential 元数据（状态、epoch），不含密文 |
| POST | `/v1/credentials` | 管理员 | `{"credential_id","provider","secret"}`，epoch 从 1 开始 |
| POST | `/v1/credentials/{id}/rotate` | 管理员 | `{"secret"}`，epoch+1 |
| POST | `/v1/credentials/{id}/{disable\|enable\|revoke\|compromise\|destroy}` | 管理员 | 每次 epoch+1，旧 epoch 的 Capability 随即失效 |
| GET | `/v1/audit?from=&limit=` | 公开 | 审计哈希链导出 |
| GET | `/v1/audit/checkpoints` | 公开 | SM2 签名检查点 |
| POST | `/v1/audit/checkpoints` | 管理员 | 为当前链头生成检查点 |
| GET | `/v1/audit/verify` | 公开 | Broker 侧完整复核：`{valid, entries, checkpoints, head_hash, error?}` |
| GET | `/v1/metrics` | 公开 | 各阶段 count / mean / P50 / P95 / P99 / max（毫秒） |
| POST | `/v1/metrics/reset` | 管理员 | 清空指标 |
| POST | `/v1/admin/reset` | 管理员 | 清空全部 Broker 状态；需 `BROKER_ENABLE_RESET=1`，否则 403 `RESET_DISABLED` |

管理员接口要求 `Authorization: Bearer $BROKER_ADMIN_TOKEN`，Agent 不持有这个令牌。

Mock 上游（`:9090`）：`GET|PUT /git/repos/{repo}/files/{path}`、`POST /db/{db}/query|update`（都要求 Credential），`GET /stats`、`POST /reset`。

### A/B Credential Status 契约

A 的 `BROKER_LIVE` 模式会在签发前读取：

```text
GET /v1/credentials/{credential_id}/status
Accept: application/json
```

B 返回的 `Info` 字段与 `shared/schemas/credential-status.schema.json` 一致：

```json
{
  "credential_id": "github-prod",
  "provider": "github",
  "status": "ACTIVE",
  "credential_epoch": 17,
  "created_at": 1791975000,
  "updated_at": 1791975000
}
```

- 该端点只返回非秘密生命周期元数据，不返回密文或明文；
- A 的失败关闭错误码：`CREDENTIAL_STATUS_UNAVAILABLE`、`CREDENTIAL_STATUS_INVALID`、`CREDENTIAL_STATUS_MISMATCH`、`CREDENTIAL_INACTIVE`；
- B 的执行期错误码：`CREDENTIAL_EPOCH_MISMATCH`、`CREDENTIAL_INACTIVE`；
- A 的预检查不替代 B 在执行事务内的原子检查；轮换/撤销竞态仍由 B 的线性化点裁决。

### `POST /v1/execute`

请求体是 `shared/schemas/execution-bundle.schema.json` 定义的结构，Broker 原样按字节交给流水线严格解析。成功时的响应（有删节）：

```json
{
  "decision": {
    "allowed": true,
    "steps": [{"step": "schema", "passed": true, "duration_ms": 0.08}, "..."]
  },
  "credential_loaded": true,
  "replayed": false,
  "result": {"status": 200, "body": {"repo": "course-project", "path": "README.md", "content": "..."}, "replay": false},
  "result_envelope": {"capability_id": "cap_…", "code": null, "outcome": "SUCCESS", "protocol_version": "1.0",
                      "request_hash": "…", "upstream_body": {"…": "…"}, "upstream_status": 200},
  "receipt": {"body": {"protocol_version": "1.0", "receipt_id": "rcpt_…", "broker_id": "broker-01",
                       "broker_key_id": "broker-key-01", "capability_id": "cap_…", "request_hash": "…",
                       "credential_id": "github-prod", "credential_epoch": 17, "result_hash": "…",
                       "outcome": "SUCCESS", "executed_at": 1791975012},
              "signature": {"algorithm": "SM2-SM3", "encoding": "ASN.1-DER/base64url-nopad",
                            "sm2_user_id": "1234567812345678", "key_id": "broker-key-01", "value": "…"}}
}
```

拒绝时 `decision` 中带 `failed_step`、`code`、`reason`。HTTP 状态码按拒绝码确定：

| HTTP | 拒绝码 |
|---|---|
| 200 | 已执行（包括上游返回 4xx 的情况：Receipt `outcome=ERROR`，`code=UPSTREAM_REJECTED`） |
| 400 | `CANONICALIZATION_ERROR`、`SCHEMA_VALIDATION_FAILED` |
| 403 | 签名 / 密钥类：`INVALID_SIGNATURE`、`INVALID_SIGNATURE_ENCODING`、`SIGNATURE_KEY_MISMATCH`、`UNTRUSTED_ISSUER`、`UNKNOWN_KEY`、`KEY_REVOKED`、`WRONG_KEY_PURPOSE`、`KEY_SUBJECT_MISMATCH`、`KEY_OUTSIDE_VALIDITY` |
| 403 | 时间 / 绑定类：`CAPABILITY_NOT_YET_VALID`、`CAPABILITY_EXPIRED`、`AUDIENCE_MISMATCH`、`REQUEST_BINDING_MISMATCH`、`REQUEST_HASH_MISMATCH`、`HOLDER_BINDING_MISMATCH`、`PROOF_NOT_YET_VALID`、`PROOF_EXPIRED`、`UNSUPPORTED_OPERATION` |
| 403 | Challenge：`CHALLENGE_UNKNOWN`、`CHALLENGE_USED`、`CHALLENGE_EXPIRED`、`CHALLENGE_WRONG_AGENT`、`CHALLENGE_WRONG_AUDIENCE` |
| 403 | 生命周期：`CREDENTIAL_NOT_FOUND`、`CREDENTIAL_INACTIVE`、`CREDENTIAL_EPOCH_MISMATCH`、`CREDENTIAL_UNAVAILABLE`、`CAPABILITY_ALREADY_FAILED` |
| 409 | `REPLAY_IN_PROGRESS`、`IDEMPOTENCY_CONFLICT`、`CAPABILITY_CLAIM_MISMATCH`、`CAPABILITY_NONCE_REUSED` |
| 502 | `UPSTREAM_ERROR`（赢得执行权后上游不可达或返回 5xx；Capability → `FAILED`） |
| 500 | `INTERNAL_ERROR`（如 Challenge 存储不可用，同样拒绝） |
| 503 | `EXECUTION_DISABLED`（未配置 `BROKER_TRUSTED_ISSUER` / `BROKER_KEY_REGISTRY`） |

协议类错误码沿用 A 的 `errors.py`。生命周期、重放和上游类错误码是 B 扩展的，定义在 `internal/errcode`。

### Execution Receipt

- **签名**：`SM2-with-SM3(Broker 私钥, "AACRED"‖0‖"EXECUTION_RECEIPT"‖0‖"v1"‖0‖ZTCANON(body))`，DER 编码后转 base64url，UID 为 `1234567812345678`。与 `docs/crypto-protocol.md` §3 一致，A 的 `ReceiptVerifier` 可以直接验签。
- **公钥**：`GET /v1/broker/key-registry`，用途 `RECEIPT_SIGNING`，主体为 `broker_id`。`not_before` 取签名密钥文件的修改时间，所以重启后旧回执仍然在有效期内。
- **何时签发**：

  | outcome | 场景 | Capability 状态 |
  |---|---|---|
  | `SUCCESS` | 上游返回 2xx | `CONSUMED` |
  | `ERROR` | 上游返回 3xx/4xx（`UPSTREAM_REJECTED`） | `CONSUMED` |
  | `ERROR` | 上游失败（`UPSTREAM_ERROR`），或消费后 Credential 已变化（`CREDENTIAL_UNAVAILABLE`） | `FAILED` |
  | `DENIED` | Capability **已通过验签**之后的任何拒绝（过期、绑定、Challenge、Epoch……） | 不变 |
  | 不签发 | `schema` / `capability_signature` 阶段的拒绝 | — |

  Capability 验签通过之前，它的字段可能是伪造的，Broker 不为这类内容签名。同一 Capability 带新 Challenge 再次提交时（幂等重放），返回的是**字节相同**的原回执。

- **`result_envelope`**：`result_hash = SM3(ZTCANON(result_envelope))`。结构已固化为 `shared/schemas/result-envelope.schema.json`，跨语言向量为 `shared/test-vectors/result-envelope-v1.json`（`internal/receipt/vector_test.go` 逐字节核对）。

  ```json
  {
    "protocol_version": "1.0",
    "capability_id": "<Capability ID>",
    "request_hash": "<Capability 中签名的 request_hash>",
    "outcome": "SUCCESS | DENIED | ERROR",
    "code": "<拒绝 / 错误码，SUCCESS 时为 null>",
    "upstream_status": "<上游 HTTP 状态码，未调用上游时为 null>",
    "upstream_body": "<上游 JSON；不符合 ZTCANON-JSON-v1（如含浮点）时为原始文本字符串；未调用上游时为 null>"
  }
  ```

  调用方复核：A 的 `ReceiptVerifier.verify_result()` 依次验签、重算 `result_hash`、比对 `capability_id` / `request_hash` / `outcome`。`scripts/verify-a-receipt.py` 和 `scripts/e2e-demo.py` 都用它复核真实 Broker 的输出。

## 面向 C 的实验支撑

C 的实验记录字段（`evaluation-dashboard/contracts/README.md`）可以从这些接口取得：

| C 字段 | 来源 |
|---|---|
| `actual_decision` / `error_code` | `/v1/execute` 响应的 `decision.allowed` / `decision.code` |
| `credential_accessed` | `/v1/execute` 响应的 `credential_loaded` |
| `side_effect_count` | Mock `GET /stats` 的 `by_capability[<capability_id>]`（写操作实际生效次数），以及 `side_effects`、`calls`、`auth_failures`、`replays` |
| 最终状态 | `GET /v1/capabilities/{id}`（管理员） |
| 证据 | `receipt`（用 `/v1/broker/key-registry` 验签）、`/v1/audit` + `/v1/audit/checkpoints`（可独立复核，格式见 `docs/audit-chain.md`）、`/v1/audit/verify` |
| `latency_ms` | 客户端自测，或 `GET /v1/metrics` 的分阶段分位数 |

状态管理（仅开发 / 实验环境）：

```bash
# 环境变量：BROKER_ADMIN_TOKEN、MOCK_GIT_TOKEN、MOCK_DB_TOKEN（与 Broker / Mock 一致），可选 BROKER_URL、MOCK_URL
sh scripts/seed.sh                    # github-prod 轮换到 epoch 17（SEED_GIT_EPOCH）、db-prod epoch 1
SEED_BATCH=50 sh scripts/seed.sh      # 另建 batch-0001..0050，供并发重放 / 撤销竞态实验
sh scripts/reset.sh                   # 清空 Broker（Credential、Capability、Challenge、审计、指标）与 Mock，再 seed；SEED=0 只清空
```

脚本只依赖 POSIX sh 和 curl。管理令牌通过 0600 临时文件传给 curl，不会出现在进程参数里。已存在的 Credential 不会被 seed 覆盖。

## 配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `BROKER_ID` | `broker-01` | 本 Broker 的 audience，也是 Receipt 的 `broker_id` |
| `BROKER_ADDR` | `:8080` | 监听地址 |
| `BROKER_DB_PATH` | `data/broker.db` | SQLite（WAL，`BEGIN IMMEDIATE`） |
| `BROKER_SIGNING_KEY_FILE` | `data/broker-sm2.key` | Receipt 签名私钥（对外为 `RECEIPT_SIGNING`），不存在时生成（0600） |
| `BROKER_CHECKPOINT_KEY_FILE` | `data/broker-checkpoint-sm2.key` | 审计检查点私钥，必须与 Receipt 私钥不同，不存在时生成（0600） |
| `BROKER_VAULT_KEY` | **必填** | SM4 主密钥，32 个十六进制字符：`openssl rand -hex 16` |
| `BROKER_ADMIN_TOKEN` | **必填** | ≥16 字符：`openssl rand -hex 24` |
| `BROKER_KEY_ID` | `broker-key-01` | Receipt 签名公钥标识 |
| `BROKER_KEY_VALIDITY` | `8760h` | 公钥记录有效期 |
| `BROKER_RETIRED_KEYS` | 空 | 以前的 Receipt 签名公钥（A 的 `KeyRegistryDocument` 格式），与当前公钥一起发布；见下方“轮换 Broker 签名密钥” |
| `BROKER_TRUSTED_ISSUER` | 空 | 唯一信任的 AA issuer（A 开发运行时为 `aa-demo-01`） |
| `BROKER_KEY_REGISTRY` | 空 | AA / Agent 公钥表（A 运行时的 `public-keys.json`）；和上一项必须同时设置，否则 `/v1/execute` 返回 503 |
| `BROKER_CLOCK_SKEW` | `5s` | 只放宽“签发时间在未来”的判断，和 A 的参考校验器一致 |
| `BROKER_CHALLENGE_TTL` | `60s` | Challenge 有效期 |
| `BROKER_CHECKPOINT_EVERY` | `100` | 每 N 条审计记录自动生成签名检查点（0 关闭） |
| `BROKER_UPSTREAM_URL` | `http://127.0.0.1:9090` | 受保护服务地址 |
| `BROKER_UPSTREAM_TIMEOUT` | `10s` | 上游超时 |
| `BROKER_UPSTREAM_CA_FILE` | 空 | 校验上游证书的 CA（代替系统信任库）；需要 `https://` 上游 |
| `BROKER_UPSTREAM_CLIENT_CERT_FILE` / `BROKER_UPSTREAM_CLIENT_KEY_FILE` | 空 | 调用上游时出示的客户端证书（上游要求 mTLS 时）；必须同时设置，需要 `https://` 上游 |
| `BROKER_ENABLE_RESET` | `0` | 开放 `POST /v1/admin/reset`。**生产环境不得开启** |
| `BROKER_TLS_CERT_FILE` / `BROKER_TLS_KEY_FILE` | 空 | 同时设置时以 HTTPS 监听（TLS ≥ 1.2）；只设一个则启动失败 |
| `BROKER_TLS_CLIENT_CA_FILE` | 空 | 设置后要求并校验客户端证书（mTLS），需要先开启 TLS |
| `BROKER_LOG_LEVEL` | `info` | 日志只记录方法、路径、状态码、耗时，从不记录请求体或头部 |
| `MOCK_ADDR` / `MOCK_GIT_TOKEN` / `MOCK_DB_TOKEN` | `:9090` / 必填 / 必填 | Mock 上游期望的 Credential，必须和录入 Vault 的值一致 |
| `MOCK_TLS_CERT_FILE` / `MOCK_TLS_KEY_FILE` / `MOCK_TLS_CLIENT_CA_FILE` | 空 | Mock 以 HTTPS 监听；设置客户端 CA 后，Git / DB 接口只接受该 CA 签发的客户端证书（403 `client certificate required`），`/stats`、`/reset`、`/health` 不受影响 |

## 轮换 Broker 签名密钥

```bash
# 1. 保存当前公钥记录（轮换后旧回执要靠它验证）
curl -s $BROKER_URL/v1/broker/key-registry > retired.json
# 2. 正常下线：保留 "status": "ACTIVE"，旧回执在 [not_before, not_after) 内仍可验证
#    密钥泄露：改为 "status": "REVOKED"，验证方拒绝它签的全部回执
# 3. 换新密钥与新标识后重启
export BROKER_SIGNING_KEY_FILE=data/broker-sm2-02.key BROKER_KEY_ID=broker-key-02 BROKER_RETIRED_KEYS=retired.json
```

`BROKER_RETIRED_KEYS` 中每条记录必须是本 Broker 的 `RECEIPT_SIGNING` 公钥，`key_id` 与公钥都不能和当前密钥相同，否则 Broker 拒绝启动。`/v1/broker/key-registry` 的输出已包含更早的旧公钥，所以每次轮换前保存它的完整输出即可。

## 测试

```bash
make test          # 全部单元 / 集成测试
make test-race     # 带竞态检测（并发重放 / 撤销竞态）
make vet
make interop       # 跨语言：A 的 Python 代码签发 bundle → Go 执行并签发 Receipt → A 的 ReceiptVerifier 复核
```

覆盖范围包括：

- 三组共享向量，篡改后的版本全部失败
- 23 类拒绝都停在预期步骤，没有读取 Credential，也没有调用上游
- 每类拒绝的回执行为
- 崩溃遗留的 `CONSUMING` 在启动时转为 `FAILED`，且不能再次消费
- 公钥表热加载：吊销立即生效，非法文件不替换旧表
- TLS / mTLS：无客户端证书或非受信 CA 签发的证书握手失败
- 上游 mTLS：持有正确 Credential 但没有 Broker 客户端证书的调用方被 Mock 拒绝，无副作用
- 旧 Receipt 公钥发布：`ACTIVE` 仍可验证，`REVOKED` 被拒绝，非法配置拒绝启动
- 审计条目为 `ZTCANON-JSON-v1`，旧格式条目仍可复核
- 原样重放；同一 Capability 带新 Challenge 时幂等返回同一回执
- 20 路并发重放写操作，副作用恰好一次
- 上游 4xx / 不可达
- 通过 HTTP 的执行、管理、重置、审计复核
- 响应、审计和日志中都不出现 Credential 明文

## 目录

```text
cmd/broker            Broker 入口：配置 → 依赖装配 → HTTP 服务
cmd/mock-upstream     受保护的 Mock Git / DB
internal/api          HTTP 接口（execute.go：执行、公钥记录、Capability 状态、审计复核、重置）
internal/verifier     校验流水线（steps.go）与请求映射（plan.go）
internal/execution    可信执行路径：消费 → 解密 → 上游 → 回执
internal/receipt      Execution Receipt 与 result_envelope
internal/protocol     A 协议对象的 Go 严格实现、请求摘要、SM2 域分离签名、可信公钥表
internal/canonical    ZTCANON-JSON-v1 严格解析与编码
internal/capability   原子消费、重放防护、幂等
internal/credential   Credential 生命周期与 Epoch
internal/vault        SM4-GCM Vault
internal/challenge    Broker Challenge
internal/evidence     SM3 审计哈希链 + SM2 检查点
internal/upstream     Mock 服务与上游客户端
internal/errcode      B 扩展错误码与 HTTP 状态映射
scripts/              seed / reset、跨语言联调（gen-a-bundle.py、verify-a-receipt.py）、全链路演示（e2e-demo.py）
deploy/               docker-compose.yml、AA / Dashboard 镜像、gen-env.sh
docs/                 设计说明、威胁与防御对照、答辩材料
```

## 已知限制

- **Credential Epoch 来源**：A 默认 `STATIC_DEMO` 仍把 epoch 写死为 17；A 已实现可选的 `BROKER_LIVE`，通过 `GET /v1/credentials/{id}/status` 获取实时 epoch。A+B 生命周期联调（轮换、撤销、Status 不可用/伪造、撤销竞态）已对真实进程完成；`seed.sh` 仍把 `github-prod` 轮换到 17 以兼容默认演示。B 执行事务内的 `ACTIVE + epoch` 检查仍是最终线性化点。
- **错误码与 HTTP 状态码**：全部错误码已合并进统一错误码表 [`docs/error-codes.md`](../docs/error-codes.md)，`internal/errcode/errcode_test.go` 与 A 的 `test_error_codes_doc.py` 会在出现未登记的错误码时失败。HTTP 状态按接口映射：A 的参考验签接口返回 401，Broker 对同一错误码返回 403；Challenge 方面 Broker 细分为 5 个码，A 的参考校验器只有 `CHALLENGE_MISMATCH`。以错误码为准，C 的实验脚本无需改动。
- **从旧版本升级**：检查点改用独立密钥后，旧数据库中由 Receipt 密钥签的检查点无法通过 `/v1/audit/verify`。开发 / 实验环境请执行一次 `reset`。
- **DENIED 回执**：只为已验签的 Capability 签发，每次拒绝多一次 SM2 签名。实测（`go test -bench . ./internal/receipt/`，Ryzen 9 8945HX）签一张 DENIED 回执约 0.036 ms，而能拿到回执的拒绝之前至少已做过一次约 0.049 ms 的 Capability 验签；C 测得单并发 ALLOW 路径 P50 约 4.7 ms。开销不到 1%，因此保持始终签发。
- **外部 API 成功但状态未落盘**：上游已执行而 Broker 写库前崩溃时，Capability 会停在 `CONSUMING`。重启时 Broker 把它们改为 `FAILED`，之后的提交返回 `CAPABILITY_ALREADY_FAILED`，不会重复执行；Agent 需要重新申请 Capability（新 Capability 的幂等键不同，上游无法去重）。恢复只在启动时进行，前提是同一数据库只有一个 Broker 进程。
- **公钥轮换**：AA / Agent 公钥表可以用 `SIGHUP` 热加载。Broker 自己的 Receipt 密钥通过 `BROKER_RETIRED_KEYS` 轮换（旧公钥继续发布，泄露的标记为 `REVOKED`），但需要重启 Broker。审计检查点密钥换了以后，旧检查点无法用新公钥复核，换之前应先导出并保存旧公钥。
- **传输层算法**：TLS 使用 Go 标准库（ECDSA / RSA 证书），不是国密 TLCP；协议层的签名与摘要仍是 SM2 / SM3。
- **`POST /v1/admin/reset`** 会清空审计链，只能用于开发和实验环境。
- **上游网络隔离**：默认 Demo 中 Mock 上游可以从本机直接访问（没有 Credential 只会返回 401）。设置 `MOCK_TLS_CLIENT_CA_FILE` 与 `BROKER_UPSTREAM_CLIENT_*` 后，受保护接口只接受 Broker 的客户端证书，即使 Credential 泄露也不能绕过 Broker 直接调用。真实上游需要自身支持 mTLS 或依赖网络策略。

完整的限制与可能的改进见 [docs/architecture.md §11](docs/architecture.md#11-已知限制)。
