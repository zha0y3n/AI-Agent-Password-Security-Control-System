# 面向 AI Agent 的密码凭据零接触使用与生命周期联动安全控制系统

AI Agent 即使被 Prompt Injection、恶意 RAG 文档、恶意网页或工具返回值诱导，也无法绕过密码授权边界，用长期 Credential 产生超出授权范围的真实业务副作用。Agent 只持有一次性、强绑定的 Capability，从不接触目标服务的长期 Credential。

## 系统组成

| 模块 | 语言 | 职责 |
|---|---|---|
| [`agent-aa/`](agent-aa/README.md) | Python | Agent 与 Authorization Authority：把任务变成明确请求，按服务端可信任务库授权，签发 SM2 Capability，生成 Holder Proof，验证执行回执 |
| [`credential-broker/`](credential-broker/README.md) | Go | Credential Broker 与 Vault：校验 Capability 与 Holder Proof，原子消费，从 SM4-GCM Vault 解密 Credential 代为调用上游，签发回执，维护 SM3 审计哈希链 |
| [`evaluation-dashboard/`](evaluation-dashboard/README.md) | Python | 安全评测与可视化：7 类攻击、并发、撤销与性能实验，Streamlit Dashboard |
| [`shared/`](shared/README.md) | JSON | 跨语言协议产物：JSON Schema 与测试向量 |

```text
用户任务
  │
  ▼
agent-aa
  ├─ DeterministicAgent：把任务变成明确 AgentRequest
  ├─ 可信 TaskStore + AuthorizationPolicy：服务端精确匹配
  ├─ Capability：SM2-with-SM3 签名，绑定 Agent/Task/Service/Resource/
  │   Operation/RequestHash/Audience/Credential ID+Epoch/TTL/Nonce
  ├─ HolderProof：绑定 CapabilityHash/RequestHash/Audience/Challenge
  └─ ReceiptVerifier：验证 Broker 签发的 Execution Receipt
  │
  ▼  Execution Bundle = request + capability + holder_proof
credential-broker
  ├─ 严格 schema / ZTCANON-JSON-v1
  ├─ Capability 验签、时间、audience、请求绑定
  ├─ Holder Proof + Broker Challenge 原子消费
  ├─ 同一事务：Credential ACTIVE + epoch 检查 → Capability CAS
  ├─ Vault（SM4-GCM，AAD 绑定 id/provider/epoch）解密
  ├─ 调用受保护上游；Credential 不返回 Agent
  ├─ Execution Receipt + result_envelope
  └─ SM3 审计哈希链 + SM2 签名检查点
  │
  ▼
evaluation-dashboard
  ├─ 7 类独立实验 → results/*.csv
  └─ Streamlit Dashboard
```

## 信任边界

```text
不可信：用户输入 / 外部内容 / LLM / Agent Request
                    │
                    ▼
可信：AA TaskStore + Policy + SM2 签名
                    │ Signed Capability
                    ▼
半可信：Agent / Holder Signer（只持有 Holder 私钥）
                    │ request + capability + proof
                    ▼
可信：Broker 状态库 + Vault + 受保护上游
```

安全不变量：

- AA 只依据服务端可信 TaskStore 授权；Agent 提交的上下文是数据，不是授权证明；
- Agent 永远不持有目标业务长期 Credential、Vault 主密钥或 Broker 管理令牌；
- Capability 绑定 Agent/Key、Task、Service、Resource、Operation、RequestHash、Audience、Credential ID/Epoch、TTL、Nonce 和一次性语义；
- Holder Proof 绑定 Capability 哈希、实际请求哈希、Broker audience 和新鲜 Challenge；
- Broker 在同一线性化事务中检查 `ACTIVE + epoch` 并原子消费 Capability；
- 所有 parse/schema/key/signature/time/lifecycle/replay/binding 异常一律失败关闭；
- SM2/SM3/SM4 全部来自成熟库（Python：铜锁 `tongsuopy`；Go：`emmansun/gmsm`），不自研密码原语。

## 国密算法

| 算法 | 用途 |
|---|---|
| SM2（with SM3，UID `1234567812345678`） | AA 签 Capability；Agent 签 Holder Proof；Broker 签 Execution Receipt 与审计检查点 |
| SM3 | 规范化请求摘要；Capability 哈希；结果摘要；审计哈希链 |
| SM4-GCM | Vault 中长期 Credential 的认证加密，AAD 绑定 `credential_id ‖ provider ‖ credential_epoch` |

字节级约定见 [docs/crypto-protocol.md](docs/crypto-protocol.md)。

## 快速体验

### Docker Compose（推荐）

需要 Docker Compose v2。端口 8000/8080/9090/8501 只绑定 127.0.0.1。

```bash
cd credential-broker/deploy
sh gen-env.sh                                       # 生成 .env：随机 Vault 主密钥、管理令牌、Mock Credential
docker compose up -d --build                        # AA :8000、Broker :8080、Mock 上游 :9090，并自动录入种子 Credential
docker compose run --rm e2e                         # 全链路演示 + 攻击样例
docker compose --profile dashboard up -d dashboard  # Dashboard：http://localhost:8501
docker compose run --rm reset                       # 恢复初始状态
docker compose --profile dashboard down -v          # 停止并删除全部卷
```

`e2e` 依次执行正常请求和 7 类攻击（原样重放、幂等重放、篡改请求路径、篡改 Capability、被窃取的 Capability、伪造 Challenge、提示注入），逐项打印 `[PASS]` 与拒绝码，最后核对上游只被真实调用一次、审计哈希链与检查点有效。

### 一键验证（不需要 Docker）

需要 Go、Python 3.11+、`curl`、`openssl`。

```bash
bash scripts/bootstrap.sh              # 创建 .venv 并安装 agent-aa
bash scripts/verify-all.sh             # Broker 单元测试、AA 单元测试、跨语言互操作、真实进程生命周期联调
bash scripts/verify-all.sh --compose   # 另加 Docker Compose 全链路
```

运行时、数据库和密钥都放在临时目录，监听随机空闲端口，结束后全部删除，不读写仓库中的 `.runtime/`、`.env` 或 `data/`。每一步输出 PASS / FAIL，任一步失败时退出码为 1。

生命周期联调覆盖：签发与执行之间轮换 Credential、伪造 Status、撤销后拒绝签发、Status 不可用、撤销与执行并发竞态、审计条目规范化校验。

### 只运行 AA

```bash
bash scripts/bootstrap.sh
.venv/bin/agent-aa demo                # 本地生成 Capability + Holder Proof 并验签，输出 verified: true
```

### 评测实验与 Dashboard

见 [evaluation-dashboard/README.md](evaluation-dashboard/README.md)。

## 测试与验证

| 范围 | 命令 |
|---|---|
| AA 单元 / 协议测试 | `.venv/bin/pytest agent-aa/tests -q` |
| Broker 单元 / 集成测试 | `cd credential-broker && go test -race ./...` |
| 跨语言互操作 | `cd credential-broker && make interop` |
| 真实进程生命周期联调 | `scripts/e2e-lifecycle.py`（由 `verify-all.sh` 调用） |
| Compose 全链路 | `docker compose run --rm e2e` |
| 系统实验 | `evaluation-dashboard/scripts/run_*_tests.py` |

协议单元测试、真实进程联调和系统实验各自独立出具证据，不互相替代。

## 限制与安全边界

- **至多一次，而非恰好一次**：上游执行后 Broker 崩溃时，遗留的 `CONSUMING` 在启动时改为 `FAILED`，不重试；
- **传输层**：TLS/mTLS 使用 Go/Python 标准库证书算法，不是国密 TLCP；协议层签名与摘要为 SM2/SM3；
- **密钥托管**：Vault 主密钥、管理令牌、AA/Agent 私钥以文件或环境变量提供，生产部署应接入 HSM、KMS 或独立 Holder Signer；
- **Agent**：内置固定任务的确定性 Agent，不接入 LLM；
- **部署形态**：单机 SQLite；真实上游需自身支持 mTLS 或依赖网络策略隔离。

信任假设与非目标见 [docs/threat-model.md](docs/threat-model.md)。

## 目录

```text
agent-aa/                Python：Agent + Authorization Authority
credential-broker/       Go：Credential Broker + Vault + Mock 上游 + Docker Compose
evaluation-dashboard/    Python：实验脚本、实验结果与 Dashboard
shared/                  JSON Schema 与跨语言测试向量
docs/                    协议、接口、威胁模型、审计链、错误码
scripts/                 安装、测试、联调与协议产物生成脚本
```

## 文档

- [docs/threat-model.md](docs/threat-model.md)：威胁模型与信任边界
- [docs/crypto-protocol.md](docs/crypto-protocol.md)：Canonical JSON、SM2/SM3 字节级协议
- [docs/a-b-interface.md](docs/a-b-interface.md)：AA → Broker 接口、校验顺序与 Credential Status 契约
- [docs/audit-chain.md](docs/audit-chain.md)：审计哈希链与检查点格式
- [docs/error-codes.md](docs/error-codes.md)：统一错误码表
- [credential-broker/docs/architecture.md](credential-broker/docs/architecture.md)：Broker 架构与设计说明
- [credential-broker/docs/security-mapping.md](credential-broker/docs/security-mapping.md)：威胁与防御对照
- [shared/README.md](shared/README.md)：共享协议产物与变更控制

## 协议变更规则

修改签名字段、Canonical JSON、SM2 用户 ID、签名输入、DER/base64url 编码或错误语义时，必须由 AA 与 Broker 双方共同评审，并确认是否需要升级 `protocol_version`。只有权威模型或协议字节真正变化时才重新生成 Schema 与测试向量；测试向量中的私钥仅用于互操作测试，严禁部署使用。
