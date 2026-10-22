# agent-aa：Agent 与 Authorization Authority

本模块把用户任务变成明确请求，并签发一张只能用于该任务、该 Agent、该 Broker、该 Credential 版本的一次性授权票据（Capability）。模块不实现 Broker 与 Vault，也不持有目标业务的长期 Credential。

## 组件

```text
agent.py       固定任务 Agent：生成确定性 AgentRequest
policy.py      服务端可信 TaskStore + 精确匹配授权策略
authority.py   Capability 签发与 Python 参考验签
holder.py      Holder Proof 生成/校验
receipt.py     Execution Receipt 结构与参考验签（含 result_envelope 绑定）
models.py      严格 Pydantic 协议模型
canonical.py   ZTCANON-JSON-v1
crypto.py      铜锁 SM2/SM3 封装
lifecycle.py   Broker Credential Status 失败关闭查询
runtime.py     运行目录与 STATIC_DEMO / BROKER_LIVE 配置
api.py         FastAPI 接口
cli.py         init-demo / runtime-demo / demo / serve
```

## 数据流

```text
固定任务
  → DeterministicAgent 生成 AgentRequest
  → AA 从服务端 TaskStore 读取 TaskContext
  → 策略精确匹配 AllowedAction
  → （BROKER_LIVE）查询 Broker 当前 ACTIVE Credential epoch
  → 构造 CapabilityBody 并用 AA SM2 私钥签名
  → Agent 向 Broker 申请 Challenge，用 Holder 私钥生成 Holder Proof
  → 提交 Execution Bundle 给 Broker
  → ReceiptVerifier.verify_result() 验证 Broker 回执与结果绑定
```

Capability 绑定：Agent/Key、Task、Service、Resource、Operation、RequestHash、Audience、Credential ID/Epoch、TTL、Nonce、`one_time=true`。

Holder Proof 绑定：Capability 哈希、实际请求哈希、Broker Audience、Challenge、有效期。

## 安装与验证

要求 Python 3.11+。密码原语使用铜锁 `tongsuopy==1.0.1`，不包含自研 SM2/SM3/SM4。

```bash
python3 -m venv .venv
.venv/bin/pip install -e './agent-aa[dev]'
.venv/bin/pytest agent-aa/tests -q
.venv/bin/agent-aa demo                # 输出 verified: true
```

若 PyPI 默认源不可达，可显式指定镜像：

```bash
.venv/bin/pip install -i https://mirrors.aliyun.com/pypi/simple -e './agent-aa[dev]'
```

## 运行 AA

```bash
.venv/bin/agent-aa init-demo --directory .runtime
.venv/bin/agent-aa serve --directory .runtime --host 127.0.0.1 --port 8000
# 或
bash scripts/run-a.sh
```

`init-demo` 在 gitignored 的 `.runtime/` 中生成 AA/Agent 私钥、公钥表和可信任务库。私钥文件会尝试设为 `0600`；Windows/WSL 挂载盘可能仍报告 `0777`，此时 CLI 会告警。生产环境必须改用 Linux 访问控制、Secret Manager 或 HSM/独立签名器，并将 AA 与 Agent 私钥隔离在不同进程或主机。AA `serve` 不加载 Agent 私钥。

接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/v1/public-keys/{key_id}` | AA/Agent 公钥查询 |
| POST | `/v1/capabilities/issue` | 请求体只接受 `AgentRequest + ttl_seconds`；可信 TaskContext 从 AA 本地读取 |
| POST | `/v1/capabilities/verify` | Python 参考验签（正式校验点是 Broker） |
| POST | `/v1/receipts/verify` | Broker Receipt 验签 |

请求体上限 1 MiB，深层嵌套 JSON 返回 400。完整字段与校验顺序见 [../docs/a-b-interface.md](../docs/a-b-interface.md)。

## Credential Epoch 的两种模式

### STATIC_DEMO（默认）

`init-demo` 生成 `STATIC_DEMO` 配置，可信任务中的 `credential_epoch=17` 固定不变，用于不连接 Broker 的本地演示。**生产签发不得依赖固定 epoch。**

### BROKER_LIVE

部署时把 `.runtime/config.json` 改为：

```json
{
  "credential_status_mode": "BROKER_LIVE",
  "broker_status_endpoints": {
    "broker-01": "https://broker.internal.example"
  },
  "broker_status_timeout_seconds": 2,
  "allow_insecure_broker_status_urls": false,
  "broker_status_ca_file": "broker-ca.pem",
  "broker_status_client_cert_file": "aa-client.pem",
  "broker_status_client_key_file": "aa-client.key"
}
```

三个 TLS 字段都是可选的，路径相对于运行时目录：

- `broker_status_ca_file`：用部署 CA 代替系统信任库校验 Broker 证书；
- `broker_status_client_cert_file` / `broker_status_client_key_file`：Broker 开启 mTLS（`BROKER_TLS_CLIENT_CA_FILE`）时出示的 AA 客户端证书，必须同时设置。

任一文件无法加载、证书与私钥只配了一个、或者在 HTTP 端点上配置 TLS 字段，AA 都会拒绝启动。所有活跃任务的 audience 都必须配置 Status 端点。

AA 只在 AgentRequest 已完整匹配服务端 `AllowedAction` 后，查询该 audience 对应的：

```text
GET /v1/credentials/{credential_id}/status
Accept: application/json
```

响应必须严格为：

```json
{
  "credential_id": "github-prod",
  "provider": "git",
  "status": "ACTIVE",
  "credential_epoch": 18,
  "created_at": 2000000000,
  "updated_at": 2000000010
}
```

失败关闭规则：

- `CREDENTIAL_STATUS_UNAVAILABLE`：超时、网络错误、重定向、非 200、未配置 audience；
- `CREDENTIAL_STATUS_INVALID`：响应超过 16 KiB、非严格 JSON、缺失/未知字段或类型非法；
- `CREDENTIAL_STATUS_MISMATCH`：返回的 Credential ID 与可信 Action 不同；
- `CREDENTIAL_INACTIVE`：状态不是 `ACTIVE`。

默认仅允许 HTTPS（TLS ≥ 1.2）；本机 Docker/loopback 如只能使用 HTTP，必须显式设置 `allow_insecure_broker_status_urls=true`，且只能用于开发环境。

**边界：** AA 的签发前查询只缩短状态陈旧窗口，不替代 Broker 在执行事务内对 `ACTIVE + epoch` 的原子复核。

## 测试覆盖

- Canonical JSON、SM3 已知答案、SM2 正常/篡改、非法 DER；
- 正常签发、错误资源/Body/Task、TTL、过期、跨任务/服务/资源/操作/路径；
- RequestHash、Audience、Wrong Holder、Challenge、Proof 过期；
- Receipt 篡改、`result_envelope` 绑定（`RESULT_BINDING_MISMATCH`）、验签 API；
- Broker Status 查询的 mTLS：受信客户端证书成功；无证书、非受信 CA 的客户端证书、非受信服务端证书均失败关闭；TLS 配置错误在启动时拒绝；
- `BROKER_LIVE` 实时 epoch 绑定、撤销状态拒绝、HTTP/响应/身份错误失败关闭；
- 真实本地 HTTP Status：重定向、超过 16 KiB、超时、坏状态行、截断响应、非 200、ID 不一致、非 ACTIVE；
- `BROKER_LIVE` 经 `/v1/capabilities/issue` 的成功路径、`STATIC_DEMO` 不查询 Broker、TTL 拒绝先于查询、先授权后查询；
- AA 请求体 1 MiB 上限、深层嵌套 JSON 返回 400 而非 500；
- 错误码表守护：返回的每个错误码都已在 `docs/error-codes.md` 登记；
- Capability、Holder Proof、Receipt 与 `result_envelope` 共享向量。

与真实 Broker 的联调使用 [`scripts/e2e-lifecycle.py`](../scripts/e2e-lifecycle.py)：ACTIVE 签发与执行、轮换后旧 Capability 被拒、伪造 Status 在执行时被拒、撤销后拒绝签发、Status 不可用失败关闭、撤销与执行竞态可线性化、审计条目规范化校验。

## 限制

- 使用固定任务 Agent，不接入 LLM；
- 文件型私钥只用于本地演示，生产应使用 HSM、Secret Manager 或独立 Holder Signer；
- 本模块只提供 Capability、Holder Proof 与 Receipt 的参考验签；Vault、原子消费与 Challenge 存储由 Broker 实现；
- “零接触”指长期业务 Credential 对 Agent 零接触，Agent 自身仍持有 Holder 私钥。

## 相关文档

- [../docs/a-b-interface.md](../docs/a-b-interface.md)：AA → Broker 接口
- [../docs/crypto-protocol.md](../docs/crypto-protocol.md)：字节级密码协议
- [../docs/error-codes.md](../docs/error-codes.md)：统一错误码表
- [../shared/README.md](../shared/README.md)：共享 Schema 与向量
