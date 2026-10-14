# 面向 AI Agent 的密码凭据零接触使用与生命周期联动安全控制系统

目标：AI Agent 即使被 Prompt Injection 等手段诱导，也无法绕过密码授权边界，用长期 Credential 产生超出授权范围的真实业务副作用。Agent 只持有一次性、强绑定的 Capability，从不接触目标服务的长期 Credential。

## 当前完成度（2026-10-12）

| 模块                    | 负责  | 状态                                        | 验证                                                         |
| ----------------------- | ----- | ------------------------------------------- | ------------------------------------------------------------ |
| A：Agent + AA（Python） | A     | 《111》第 1～6 周期 A 端交付已完成          | `pytest agent-aa/tests`：39 passed；`agent-aa demo` 闭环通过 |
| B：Broker + Vault（Go） | B     | 阶段一（1.1～1.12）已完成；阶段二～五未开始 | `go test ./...` 通过                                         |
| C：评测 + Dashboard     | C     | 早期：仅覆盖 AA 签发/验签接口               | 脚本需先启动 AA                                              |
| 全链路                  | A+B+C | **未打通**：Broker 尚无 `POST /v1/execute`  | —                                                            |

**整体约 40%。** A 签发的 Capability 目前只能由 A 的 Python 参考校验器验证，还不能在 Broker 处兑现为真实执行。

### A 已实现

- 固定任务 DeterministicAgent（不依赖大模型 API）
- 严格 Pydantic 模型、`ZTCANON-JSON-v1`，拒绝重复 key、浮点、越界整数和未知字段
- 铜锁 `tongsuopy` SM3、SM2-with-SM3
- AA 只依据服务端可信任务库授权；Capability 绑定 Agent/任务/服务/资源/操作/请求哈希/Audience/Credential ID 与 Epoch/TTL/nonce
- Holder Proof 绑定 Capability 哈希、实际请求、Broker Audience 和 Challenge
- ExecutionReceipt 结构与验签参考实现
- FastAPI、CLI、JSON Schema、跨语言测试向量

### B 已实现（阶段一）

国密封装（SM3/SM4-GCM/SM2）、SQLite 数据层、SM4-GCM Vault（AAD 绑定 id/provider/epoch）、Credential 生命周期与 Epoch、原子消费（CAS）、幂等、Mock Git/DB 上游、SM3 哈希链审计 + SM2 检查点、Challenge、性能埋点、Dockerfile。详见 [docs/b-progress.md](docs/b-progress.md)。

### C 已实现

AA 签发接口攻击用例（`tests/test_aa_issue.py`、`scripts/run_security_tests.py`）、AA 验签接口攻击用例（`scripts/run_verify_tests.py`）、探测脚本，以及读取 `results/*.csv` 的 Streamlit Dashboard 雏形。

### 已知问题

- **AA 验签 500**：签名值被篡改成非法 DER（如前缀改为 `AAAA`）时，`/v1/capabilities/verify` 返回 500，而不是 401 `INVALID_SIGNATURE`。请求仍被拒绝，但违反了“失败即明确拒绝”的约定。由 C 在 `a2d7a6c` 中发现；根因是 `agent-aa/src/agent_aa/crypto.py` 的 `verify_sm2` 未捕获 tongsuopy 的 `InternalError`。待 A 修复。
- C 的脚本依赖 `requests`、`streamlit`、`pandas`，尚未声明在任何依赖文件中。

## 待办（按依赖顺序）

1. **A+B 协议对齐**：完成 [docs/b-plan.md](docs/b-plan.md) §2.1 清单（签名/公钥编码、SM2 ID、签名输入、Challenge 格式、错误码、Receipt 返回方式）。
2. **B 阶段二**：Go Canonical JSON 与 Request Hash；Go 验证 `shared/test-vectors/sm2-sm3-v1.json` 三组向量；填充 `internal/verifier` 校验步骤；实现 `POST /v1/execute`（校验 → 消费 → Vault 解密 → Mock API → Receipt → 审计）。
3. **A+B 联调**：Agent → AA → Capability → Challenge → Holder Proof → Broker → Vault → Mock API → Receipt → Audit，并逐条验证攻击样例被拒绝。
4. **B 阶段四**：`docker-compose.yml`（AA + Broker + Mock + Dashboard）、重置脚本、种子数据。
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

要求 Go（见 `credential-broker/go.mod`）。

```bash
cd credential-broker
make test           # 或 make test-race / make vet
cp .env.example .env   # 填写 BROKER_VAULT_KEY（openssl rand -hex 16）和 BROKER_ADMIN_TOKEN（至少 16 位）
set -a; . ./.env; set +a
make run-mock       # Mock Git/DB 上游，:9090
make run            # Broker，:8080
```

当前 HTTP 接口包括健康检查、Broker 公钥、Challenge、Credential 状态与生命周期管理、审计记录与检查点、Metrics，完整列表见 [docs/b-progress.md](docs/b-progress.md)。**执行接口 `/v1/execute` 尚未实现。**

## C：评测

先启动 AA（`bash scripts/run-a.sh`），然后：

```bash
.venv/bin/pip install requests pandas streamlit
mkdir -p evaluation-dashboard/results
.venv/bin/pytest evaluation-dashboard/tests -q
.venv/bin/python evaluation-dashboard/scripts/run_security_tests.py
.venv/bin/python evaluation-dashboard/scripts/run_verify_tests.py
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
