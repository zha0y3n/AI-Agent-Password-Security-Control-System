# 面向 AI Agent 的密码凭据零接触使用与生命周期联动安全控制系统

目标：AI Agent 即使被 Prompt Injection 等手段诱导，也无法绕过密码授权边界，用长期 Credential 产生超出授权范围的真实业务副作用。Agent 只持有一次性、强绑定的 Capability，从不接触目标服务的长期 Credential。

## 当前完成度（2026-10-22）

| 模块                    | 负责  | 状态                                                                 | 验证                                                                  |
| ----------------------- | ----- | -------------------------------------------------------------------- | --------------------------------------------------------------------- |
| A：Agent + AA（Python） | A     | 《111》第 1～6 周期 A 端交付已完成；非法 DER 验签 500 已修复（PR #5）；新增可选 Broker 实时 Credential Epoch 绑定 | `pytest agent-aa/tests`：50 passed；`agent-aa demo` 闭环通过          |
| B：Broker + Vault（Go） | B     | 阶段一～五完成（`/v1/execute`、Receipt、HTTP 联调、C 支撑、docker compose、设计与答辩文档）；待 A/C 联审 | `go test -race ./...` 通过；`make interop` 通过（A 的 `ReceiptVerifier`）       |
| C：评测 + Dashboard     | C     | 已提交七类实验脚本、`results/*.csv` 与 Dashboard 更新；待干净环境复现 | 见 `evaluation-dashboard/README.md` 与 `results/`                    |
| 全链路                  | A+B+C | **A+B 已经 HTTP 打通**；C 已提交系统实验结果，待复现                  | compose 内 e2e 14/14；C 的 CSV 结果待 C 从干净环境确认               |

**整体约 70%（2026-10-18 统计）**（三方等权粗估：A 约 95%，B 约 90%，C 约 25%）。该比例尚未计入 C 在 2026-10-19/20 提交的七类实验 CSV 与 Dashboard 更新；C 的最新产物见 `evaluation-dashboard/results/`，待 C 从干净环境复现后再统一更新本表。Agent → AA → Challenge → Holder Proof → Broker → Vault → Mock → Receipt → Audit 已通过真实 HTTP 跑通，Go 签发的 Receipt 能被 A 的 `ReceiptVerifier` 验过，重放、篡改、窃取、伪造 Challenge、提示注入、旧 Epoch 均被拒绝。

### A 已实现

- 固定任务 DeterministicAgent（不依赖大模型 API）
- 严格 Pydantic 模型、`ZTCANON-JSON-v1`，拒绝重复 key、浮点、越界整数和未知字段
- 铜锁 `tongsuopy` SM3、SM2-with-SM3
- AA 只依据服务端可信任务库授权；Capability 绑定 Agent/任务/服务/资源/操作/请求哈希/Audience/Credential ID 与 Epoch/TTL/nonce
- Holder Proof 绑定 Capability 哈希、实际请求、Broker Audience 和 Challenge
- ExecutionReceipt 结构与验签参考实现
- FastAPI、CLI、JSON Schema、跨语言测试向量
- 可选的 Broker 实时 Credential Status 查询：仅在可信 Action 精确匹配后读取当前 ACTIVE epoch，查询/响应/状态异常均失败关闭

### B 已实现

阶段一（国密封装、SM4-GCM Vault、Credential 生命周期与 Epoch、原子消费、幂等、Mock 上游、审计哈希链、Challenge、埋点）、阶段二（Go `ZTCANON-JSON-v1`、SM2 域分离验签、校验流水线、`POST /v1/execute`、Execution Receipt）、阶段三 B 侧（HTTP 全链路 `scripts/e2e-demo.py`）、阶段四（Capability 状态、审计复核、状态重置、seed / 批量 Credential、docker compose）、阶段五（设计说明、威胁与防御对照、答辩材料，见 [credential-broker/docs/](credential-broker/docs/)）。详见 [credential-broker/README.md](credential-broker/README.md)。

### C 已实现

- AA 签发接口攻击用例（`tests/test_aa_issue.py`、`scripts/run_security_tests.py`）
- AA 验签接口攻击用例（`scripts/run_verify_tests.py`）
- Broker Credential 生命周期用例（`scripts/run_credential_lifecycle_tests.py`，输出 `credential_lifecycle.csv`）
- 探测脚本，以及读取 `results/*.csv` 的 Streamlit Dashboard 雏形

### 已知问题

- **Credential Epoch 来源仍有两套模式**：A 默认 `STATIC_DEMO` 仍把 Epoch 写死为 17（`agent-aa/src/agent_aa/runtime.py`、`demo.py`），便于无 Broker 演示；`BROKER_LIVE` 会在签发前读取 Broker 当前 `ACTIVE` epoch。真实 A+B 生命周期联调（轮换、撤销、Status 不可用/伪造、撤销竞态）尚未完成。`credential-broker/scripts/seed.sh` 仍会把 `github-prod` 轮换到 17 以兼容默认演示。
- **`result_envelope` 未固化**：结构是 B 的提案（见 `credential-broker/README.md`），A/C 联审后需写入 `shared/`。
- **`run_credential_lifecycle_tests.py` 在源码中硬编码了 `ADMIN_TOKEN`**，违反“不提交 token”的约定，且已推送到 GitHub。如果这个值在任何环境里用过，应视为已泄露并更换；脚本应改为从环境变量读取。
- C 的脚本依赖 `requests`、`streamlit`、`pandas`，尚未声明在任何依赖文件中。

已解决：AA 对非法 DER 签名返回 500（C 发现，A 在 `d1b831b` 中修复并补了回归测试，经 PR #5 合入）。

## 待办（按依赖顺序）

1. **A+B 剩余对齐**：A 已实现可选的 `GET /v1/credentials/{id}/status` 读取（`BROKER_LIVE`），待与真实 B 做 TLS/mTLS 联调并确认缓存上限；`result_envelope` 结构与 Receipt 返回方式（B 已按提案实现）、统一错误码表（B 的映射见 `credential-broker/README.md`）仍需联审。
2. **C 移除硬编码 token 并声明依赖**：见上方已知问题。
3. **C 确认实验接口**：B 已提供副作用计数、Capability 状态、审计导出 / 复核、Receipt、Metrics、重置与批量 Credential，需 C 确认是否够用。
4. **B 收尾**：崩溃后停在 `CONSUMING` 的 Capability 的恢复流程（可选）。设计说明、威胁与防御对照、答辩材料已在 `credential-broker/docs/`。
5. **C 系统实验**：旧 Epoch、撤销、重放、并发重放、撤销竞态、提示注入、性能；输出 `security.csv`、`performance.csv`、`concurrency.csv`、`revocation.csv`、`prompt_injection.csv`，并检查实际副作用而不只是 HTTP 状态码。

## 目录

```text
agent-aa/                A：Python Agent + Authorization Authority
credential-broker/       B：Go Credential Broker + Vault + Mock 上游
evaluation-dashboard/    C：攻击脚本、实验结果与 Dashboard
shared/                  JSON Schema 与跨语言测试向量（A/B 共同评审变更）
docs/                    协议、接口、威胁模型、审计链、进度文档
scripts/                 安装、测试、启动与产物生成脚本
```

## A：Agent + AA

要求 Python 3.11+。密码原语全部来自铜锁 `tongsuopy==1.0.1`，没有自研的 SM2/SM3/SM4 实现。

```bash
bash scripts/bootstrap.sh            # 或手动：
python3 -m venv .venv
.venv/bin/pip install -e './agent-aa[dev]'
# 如果 PyPI 不可达：加上 -i https://mirrors.aliyun.com/pypi/simple
```

测试与闭环演示（A 每次改动都必须运行）：

```bash
.venv/bin/pytest agent-aa/tests -q
.venv/bin/agent-aa demo
```

`demo` 在内存中完成：固定任务 → AgentRequest → AA 策略检查 → Signed Capability → Broker Challenge → Holder Proof → Python 参考验签。过程中不生成、也不向 Agent 提供业务 Credential。

### 可选：启用 Broker 实时 Credential 生命周期绑定

`init-demo` 默认生成 `STATIC_DEMO` 配置，便于没有 Broker 的 A 端演示。生产签发不得依赖其中固定的 epoch。部署时，将 gitignored 运行目录中的 `config.json` 改为类似下列配置，并通过受 TLS/mTLS 或等效工作负载身份保护的网络访问 Broker：

```json
{
  "credential_status_mode": "BROKER_LIVE",
  "broker_status_endpoints": {
    "broker-01": "https://broker.internal.example"
  },
  "broker_status_timeout_seconds": 2,
  "allow_insecure_broker_status_urls": false
}
```

AA 只会在请求已精确匹配服务端可信任务后，查询该 audience 对应的 `GET /v1/credentials/{id}/status`。查询超时、非 200、重复/未知字段、非法响应、Credential ID 不一致或状态非 `ACTIVE` 都会拒绝签发；返回的当前 epoch 被写入并签名到 Capability。该公开元数据查询不使用、更不会向 Agent 下发 Broker 管理令牌或 Credential 明文。Broker 仍必须在执行事务中再次原子检查状态和 epoch。

本机 Docker/loopback 联调如确实只能使用 HTTP，必须显式把 `allow_insecure_broker_status_urls` 设为 `true`；这仅限开发环境，不能作为生产配置。

启动 AA 服务（运行目录 `.runtime/` 已加入 gitignore，密钥随机生成）：

```bash
bash scripts/run-a.sh                # 等价于 init-demo + serve，监听 127.0.0.1:8000
```

| 方法 | 路径                       | 说明                                                                       |
| ---- | -------------------------- | -------------------------------------------------------------------------- |
| GET  | `/health`                  | 健康检查                                                                   |
| GET  | `/v1/public-keys/{key_id}` | 公钥查询                                                                   |
| POST | `/v1/capabilities/issue`   | 请求体只接受 `AgentRequest + ttl_seconds`；可信 TaskContext 从 AA 本地读取 |
| POST | `/v1/capabilities/verify`  | Python 参考验签（供测试；正式校验点是 Broker）                             |
| POST | `/v1/receipts/verify`      | Receipt 验签                                                               |

接口细节见 [docs/a-b-interface.md](docs/a-b-interface.md)，协议字节见 [docs/crypto-protocol.md](docs/crypto-protocol.md)。

在 WSL 挂载盘上，私钥文件的 `chmod 0600` 可能不生效（CLI 会告警）。该目录只用于本机演示。

## B：Credential Broker

要求 Go（见 `credential-broker/go.mod`），或直接用 Docker Compose：

```bash
cd credential-broker/deploy
sh gen-env.sh && docker compose up -d --build   # AA + Broker + Mock，自动 seed
docker compose run --rm e2e                      # A+B 全链路联调与攻击样例
docker compose run --rm reset                    # 实验之间恢复干净状态
```

本地运行、接口、错误码、Receipt、配置与测试见 [credential-broker/README.md](credential-broker/README.md)。

## C：评测

先启动 AA（`bash scripts/run-a.sh`）；生命周期用例还需启动 Broker（见上节）。然后：

```bash
.venv/bin/pip install requests pandas streamlit
mkdir -p evaluation-dashboard/results
.venv/bin/pytest evaluation-dashboard/tests -q
.venv/bin/python evaluation-dashboard/scripts/run_security_tests.py
.venv/bin/python evaluation-dashboard/scripts/run_verify_tests.py
.venv/bin/python evaluation-dashboard/scripts/run_credential_lifecycle_tests.py   # 需先启动 Broker（:8080），且 ADMIN_TOKEN 与 .env 一致
.venv/bin/streamlit run evaluation-dashboard/dashboard/app.py
```

`results/` 下的 CSV 不提交。A 的 pytest 结果只是协议单元测试，不能当作全系统安全结论。

## 共享协议产物

修改权威模型或协议字节后，才重新生成：

```bash
.venv/bin/python scripts/generate-schemas.py
.venv/bin/python scripts/generate-test-vectors.py
```

向量中的私钥标量只用于测试，严禁部署使用。涉及签名字段、规范化、签名输入、SM2 用户 ID、编码或错误语义的变更，必须经过 A 和 B 共同评审。

## 文档

- [docs/threat-model.md](docs/threat-model.md)：威胁模型
- [docs/crypto-protocol.md](docs/crypto-protocol.md)：密码协议与字节格式
- [docs/a-b-interface.md](docs/a-b-interface.md)：A/B 接口
- [docs/audit-chain.md](docs/audit-chain.md)：审计链格式
- [docs/a-progress.md](docs/a-progress.md)、[docs/a-manual-review.md](docs/a-manual-review.md)：A 进度与自审
- [docs/b-plan.md](docs/b-plan.md)、[docs/b-progress.md](docs/b-progress.md)：B 计划与进度
- [credential-broker/docs/](credential-broker/docs/)：Broker 设计说明、威胁与防御对照、答辩材料
