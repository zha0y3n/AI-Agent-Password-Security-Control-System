# 面向 AI Agent 的密码凭据零接触使用与生命周期联动安全控制系统

目标：AI Agent 即使被 Prompt Injection 等手段诱导，也无法绕过密码授权边界，用长期 Credential 产生超出授权范围的真实业务副作用。Agent 只持有一次性、强绑定的 Capability，从不接触目标服务的长期 Credential。

## 项目状态（2026-10-22）

| 模块 | 负责 | 完整度 | 当前状态 | 主要证据 |
|---|---|---:|---|---|
| A：Agent + AA（Python） | A | **95%** | 第 1～6 周期 A 范围完成；Capability/Holder Proof/Receipt 参考实现；新增可选 Broker 实时 Credential Epoch 绑定与 P0 硬化 | `pytest agent-aa/tests -q`：71 passed；`agent-aa demo`：`verified: true` |
| B：Broker + Vault（Go） | B | **92%** | 阶段一～五完成；`/v1/execute`、Vault、原子消费、Receipt、审计链、Compose、E2E 已具备 | B 文档记录：`go test -race ./...`、`make interop`、Compose E2E 14/14 |
| C：评测 + Dashboard | C | **88%** | 7 类实验脚本、7 份 CSV、7 Tab Dashboard、一键启动已提交 | 已提交 CSV 共 110 条记录，全部标记通过；待干净环境复现 |
| 全链路 | A+B+C | **92%** | A+B 已通过真实 HTTP 跑通；A 的 `BROKER_LIVE` 已合入；C 的系统实验已落盘 | 三方等权自评；最终以干净环境复现和答辩材料为准 |

> 百分比是团队按《111》功能项和现有证据的自评，不是 GitHub 贡献指标。剩余的主要是联调、复现、协议冻结和交付打包，而不是从零实现。

## 系统总框架

```text
用户任务
  │
  ▼
agent-aa（A）
  ├─ DeterministicAgent：把任务变成明确 AgentRequest
  ├─ 可信 TaskStore + AuthorizationPolicy：服务端精确匹配
  ├─ Capability：SM2-with-SM3 签名，绑定 Agent/Task/Service/Resource/
  │   Operation/RequestHash/Audience/Credential ID+Epoch/TTL/Nonce
  ├─ HolderProof：绑定 CapabilityHash/RequestHash/Audience/Challenge
  └─ ReceiptVerifier：验证 Broker 签发的 Execution Receipt
  │
  ▼  Execution Bundle = request + capability + holder_proof
credential-broker（B）
  ├─ 严格 schema / ZTCANON-JSON-v1
  ├─ Capability 验签、时间、audience、请求绑定
  ├─ Holder Proof + Broker Challenge 原子消费
  ├─ 同一事务：Credential ACTIVE + epoch 检查 → Capability CAS
  ├─ Vault（SM4-GCM，AAD 绑定 id/provider/epoch）解密
  ├─ Mock Git/DB 上游调用；Credential 不返回 Agent
  ├─ Execution Receipt + result_envelope
  └─ SM3 审计哈希链 + SM2 签名检查点
  │
  ▼
evaluation-dashboard（C）
  ├─ 7 类独立攻击/并发/性能/撤销实验
  ├─ results/*.csv
  └─ Streamlit Dashboard（7 个 Tab）
```

### 信任边界

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
- Capability 必须绑定 Agent/Key、Task、Service、Resource、Operation、RequestHash、Audience、Credential ID/Epoch、TTL、Nonce 和一次性语义；
- Holder Proof 必须绑定 Capability 哈希、实际请求哈希、Broker audience 和新鲜 Challenge；
- Broker 必须在同一线性化事务中检查 `ACTIVE + epoch` 并原子消费 Capability；
- 所有 parse/schema/key/signature/time/lifecycle/replay/binding 异常一律失败关闭；
- 不手写 SM2/SM3/SM4，不修改 SM2 ID、DER、base64url、域分离或双重哈希约定。

## A：Agent + AA（95%）

已实现：

- 固定任务 `DeterministicAgent`，不依赖大模型 API；
- 严格 Pydantic 模型、`ZTCANON-JSON-v1`，拒绝重复 key、浮点、越界整数和未知字段；
- 铜锁 `tongsuopy` SM3、SM2-with-SM3；
- AA 服务端可信 TaskStore 精确匹配；
- Capability 完整签名绑定；
- Holder Proof 生成与参考验签；
- Execution Receipt 结构与参考验签；
- FastAPI、CLI、JSON Schema、跨语言测试向量；
- 可选 `BROKER_LIVE`：在可信 Action 精确匹配后读取 Broker 当前 `ACTIVE` epoch，查询/响应/状态异常均拒绝签发；
- P0 硬化：真实 HTTP Status 测试、AA 请求体 1 MiB 上限、深层 JSON 保护、统一错误码表、A+B 生命周期联调脚本。

验证：

```bash
.venv/bin/pytest agent-aa/tests -q     # 71 passed
.venv/bin/agent-aa demo                # verified: true
```

剩余：

- 与真实 B 的 TLS/mTLS 生命周期联调（轮换、撤销、Status 不可用/伪造、撤销竞态）；
- 生产密钥托管（HSM/Secret Manager/独立 Holder Signer）；
- A 不实现 B/C 的 Vault、原子消费或系统实验。

## B：Credential Broker（92%）

已实现：

- 阶段一：国密封装、SQLite、SM4-GCM Vault、Credential 生命周期与 Epoch、原子消费、幂等、Mock 上游、审计哈希链、Challenge、埋点、Docker；
- 阶段二：Go `ZTCANON-JSON-v1`、SM2 域分离验签、可信公钥表、校验流水线、`POST /v1/execute`、Execution Receipt；
- 阶段三：A+B 真实 HTTP 全链路 `scripts/e2e-demo.py`；
- 阶段四：Capability 状态、审计复核、状态重置、seed/批量 Credential、Docker Compose；
- 阶段五：设计说明、威胁与防御对照、答辩材料。

验证（B 文档记录，2026-10-18）：

```text
go test -race ./...     通过
make interop            通过（A 的 ReceiptVerifier 验过 Go Receipt）
Compose E2E             14/14
```

剩余：

- `result_envelope` 与 Receipt 返回语义写入 `shared/`；
- A/B 统一错误码表；
- `CONSUMING` 崩溃恢复；
- Broker/AA/Agent 公钥轮换；
- Broker 与 Mock 的 mTLS/网络隔离；
- 审计条目改用 `ZTCANON-JSON-v1`。

## C：评测 + Dashboard（88%）

已提交 7 类实验：

| 实验 | 记录数 | 结果 | 关键结论 |
|---|---:|---|---|
| `security.csv` | 10 | 10/10 | AA 签发攻击均被拒绝，副作用 0 |
| `verify.csv` | 10 | 10/10 | 验签篡改/绑定错误均被拒绝 |
| `credential_lifecycle.csv` | 9 | 9/9 | 生命周期管理接口符合预期 |
| `concurrency.csv` | 15 | 15/15 | 最高 500 并发，每轮最大副作用 1 |
| `performance.csv` | 12 | 12/12 | 1/10/50/100 并发吞吐与分位数据 |
| `revocation.csv` | 50 | 50/50 safe | `execute_allowed` 全为 false，副作用 0 |
| `prompt_injection.csv` | 4 | 4/4 | 提示注入越权均被拦截 |

Dashboard 读取上述 7 份 CSV，提供 7 个 Tab。C 的 CSV 是已提交证据，仍需从干净环境复现并记录硬件、版本、启动顺序和生成时间。

剩余：

- 干净环境全量复现；
- 证据元数据与答辩材料；
- 历史提交曾出现硬编码 `ADMIN_TOKEN`；当前脚本已改为从环境变量/`.env` 读取，若该 token 在任何环境使用过必须轮换；
- C 的进度文档与最终展示口径。

## 快速开始

### A：Agent + AA

要求 Python 3.11+。密码原语全部来自铜锁 `tongsuopy==1.0.1`，没有自研的 SM2/SM3/SM4 实现。

```bash
bash scripts/bootstrap.sh
.venv/bin/pytest agent-aa/tests -q
.venv/bin/agent-aa demo
```

启动 AA：

```bash
.venv/bin/agent-aa init-demo --directory .runtime
bash scripts/run-a.sh
```

接口：`/health`、`/v1/public-keys/{key_id}`、`/v1/capabilities/issue`、`/v1/capabilities/verify`、`/v1/receipts/verify`。详见 [agent-aa/README.md](agent-aa/README.md)。

### B：Credential Broker

推荐 Docker Compose：

```bash
cd credential-broker/deploy
sh gen-env.sh
docker compose up -d --build
docker compose run --rm e2e
docker compose run --rm reset
```

本地运行、接口、错误码、Receipt 与配置见 [credential-broker/README.md](credential-broker/README.md)。

### C：评测与 Dashboard

```bash
bash evaluation-dashboard/scripts/start_all_services.sh
source .venv/bin/activate
python evaluation-dashboard/scripts/run_security_tests.py
python evaluation-dashboard/scripts/run_verify_tests.py
python evaluation-dashboard/scripts/run_credential_lifecycle_tests.py
python evaluation-dashboard/scripts/run_concurrency_tests.py
python evaluation-dashboard/scripts/run_performance_tests.py
python evaluation-dashboard/scripts/run_revocation_tests.py
python evaluation-dashboard/scripts/run_prompt_injection_tests.py
streamlit run evaluation-dashboard/dashboard/app.py
```

详见 [evaluation-dashboard/README.md](evaluation-dashboard/README.md)。

## 验证证据

| 范围 | 命令 | 结果 | 日期 |
|---|---|---|---|
| A 单元/协议 | `pytest agent-aa/tests -q` | 71 passed | 2026-10-22 |
| A+B 生命周期 | `scripts/e2e-lifecycle.py --reset` | 待 B 运行环境执行 | 2026-10-22 |
| A 闭环 | `agent-aa demo` | `verified: true` | 2026-10-22 |
| B Go | `go test -race ./...` | 通过 | 2026-10-18（B 文档） |
| B 互操作 | `make interop` | 通过 | 2026-10-18（B 文档） |
| B 全链路 | `docker compose run --rm e2e` | 14/14 | 2026-10-18（B 文档） |
| C 系统实验 | 7 个脚本 | 110 条记录全部通过 | 2026-10-20（已提交 CSV） |

注意：A 的 pytest 只是协议单元测试；C 的 CSV 是已提交实验证据。两者都不能单独替代干净环境的全系统复现。

## 已知问题与剩余工作

1. **A+B 生命周期真实联调**：A 已实现 `BROKER_LIVE`，但尚未与真实 B 完成 TLS/mTLS、轮换、撤销、Status 不可用/伪造、撤销竞态联调。
2. **`result_envelope` 未固化**：仍是 B 的提案，需 A/B/C 联审后写入 `shared/schemas/`，并统一 Receipt 返回和幂等重放语义。
3. **统一错误码表**：A 的 `CREDENTIAL_STATUS_*` 与 B 的 `CREDENTIAL_EPOCH_MISMATCH` / `CREDENTIAL_INACTIVE` 尚未合并为一张表。
4. **C 干净环境复现**：需要记录硬件、Go/Python 版本、启动顺序、CSV 生成时间；历史硬编码 token 如使用过需轮换。
5. **B 崩溃恢复**：`CONSUMING` 状态目前 fail closed，但没有恢复流程；不能声称严格 exactly-once。
6. **密钥与传输**：公钥轮换、mTLS/SPIFFE、Vault/管理令牌托管、审计条目 ZTCANON 化仍需生产化。
7. **A 的演示边界**：当前是固定任务 Agent，不接入真实 LLM；文件型私钥只用于本地演示。

## 目录

```text
agent-aa/                A：Python Agent + Authorization Authority
credential-broker/       B：Go Credential Broker + Vault + Mock 上游
evaluation-dashboard/    C：攻击脚本、实验结果与 Dashboard
shared/                  JSON Schema 与跨语言测试向量（A/B 共同评审变更）
docs/                    协议、接口、威胁模型、审计链、进度文档
scripts/                 安装、测试、启动与产物生成脚本
```

## 文档索引

- [docs/threat-model.md](docs/threat-model.md)：威胁模型与信任边界
- [docs/crypto-protocol.md](docs/crypto-protocol.md)：Canonical JSON、SM2/SM3 字节级协议
- [docs/a-b-interface.md](docs/a-b-interface.md)：A→B 接口与 Credential Status 契约
- [docs/audit-chain.md](docs/audit-chain.md)：审计哈希链与检查点格式
- [docs/error-codes.md](docs/error-codes.md)：A/B/C 统一错误码表
- [docs/a-progress.md](docs/a-progress.md)：A 进度与验证
- [docs/b-progress.md](docs/b-progress.md)：B 进度与验证
- [docs/c-progress.md](docs/c-progress.md)：C 实验进度与证据
- [agent-aa/README.md](agent-aa/README.md)：A 模块使用说明
- [credential-broker/README.md](credential-broker/README.md)：B 模块使用说明
- [evaluation-dashboard/README.md](evaluation-dashboard/README.md)：C 模块复现说明
- [shared/README.md](shared/README.md)：共享协议产物

## 协议变更规则

修改签名字段、Canonical JSON、SM2 用户 ID、签名输入、DER/base64url 编码或错误语义时，必须由 A 和 B 共同评审，并确认是否需要升级 `protocol_version`。只有权威模型或协议字节真正变化时才重新生成 Schema/测试向量；测试向量中的私钥仅用于互操作测试，严禁部署使用。
