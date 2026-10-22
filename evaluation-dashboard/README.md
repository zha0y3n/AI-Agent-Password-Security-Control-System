# evaluation-dashboard：安全评测与可视化

本模块对完整系统（AA + Broker + Mock 上游）做独立的系统级实验，并用 Dashboard 展示结果。每条实验记录都核对实际决策、是否读取了 Credential、上游真实副作用次数，不只看 HTTP 状态码。

## 目录

```text
scripts/            7 类实验脚本 + 一键启动脚本
tests/              pytest 基础用例（AA 签发接口）
dashboard/          Streamlit Dashboard（读取 results/ 下的 7 份 CSV）
contracts/          CSV 字段与跨模块数据约定
results/            实验结果 CSV；reproductions/ 下为带环境元数据的复现记录
requirements.txt    Python 依赖
```

## 实验

| 实验 | 脚本 | 结果文件 | 用例 | 通过条件 |
|---|---|---|---|---|
| AA 签发攻击 | `run_security_tests.py` | `security.csv` | 正常签发、未知任务、换资源/操作/路径/HTTP 方法、错误 Agent、未知 Agent 密钥、TTL 越界（10 条） | 攻击全部被 AA 拒绝，副作用为 0 |
| Capability 验签攻击 | `run_verify_tests.py` | `verify.csv` | 篡改签名、audience 错误、Agent/Task/Resource/Operation/Credential 绑定不一致、请求哈希不一致、过期（10 条） | 篡改与绑定错误全部被拒绝 |
| Credential 生命周期 | `run_credential_lifecycle_tests.py` | `credential_lifecycle.csv` | 创建、重复创建、无令牌创建、查询、轮换、撤销、重复撤销、查询不存在、审计记录（9 条） | 状态码与错误码符合预期 |
| 并发重放 | `run_concurrency_tests.py` | `concurrency.csv` | 同一 Capability 并发提交 10/50/100/200/500 次，各 3 轮 | 每轮恰好 1 次成功，真实副作用 ≤ 1 |
| 性能 | `run_performance_tests.py` | `performance.csv` | 并发 1/10/50/100，每轮 100 个独立 Capability，各 3 轮 | 全部执行成功；记录吞吐与 P50/P95/P99 |
| 撤销竞态 | `run_revocation_tests.py` | `revocation.csv` | 执行与撤销并发，50 轮 | 每轮 `safe`：未读取 Credential、无副作用、执行被拒 |
| 提示注入 | `run_prompt_injection_tests.py` | `prompt_injection.csv` | 任务外资源、签发后篡改请求、伪造 Capability | 全部被拦截，副作用为 0 |

性能实验的时延只统计 `POST /v1/execute`（含 Broker 全部校验、原子消费、SM4 解密、上游调用、回执签名与审计写入）；吞吐按整轮墙钟时间计算，包含 AA 签发与 Holder Proof 生成。

## 运行

前置条件：`python3`（3.11+）、`go`、`curl`、`openssl`；端口 `8000/8080/9090` 空闲。

```bash
bash evaluation-dashboard/scripts/start_all_services.sh
source .venv/bin/activate
```

启动脚本会创建 `.venv`、安装 `requirements.txt` 与 `agent-aa`、生成 `.runtime/` 与 `credential-broker/.env`（随机 Vault 主密钥与管理令牌）、在后台启动 AA :8000、Mock :9090、Broker :8080，并录入初始数据（`github-prod` 为 epoch 17）。

> **注意**：脚本开始时会执行 `pkill -f agent-aa`、`pkill -f mock-upstream`、`pkill -f broker`、`pkill -f "go run"`，会结束本机所有命令行匹配这些字样的进程。请在专用环境中运行。

依次运行实验：

```bash
python evaluation-dashboard/scripts/run_security_tests.py
python evaluation-dashboard/scripts/run_verify_tests.py
python evaluation-dashboard/scripts/run_credential_lifecycle_tests.py
python evaluation-dashboard/scripts/run_concurrency_tests.py
python evaluation-dashboard/scripts/run_performance_tests.py
python evaluation-dashboard/scripts/run_revocation_tests.py
python evaluation-dashboard/scripts/run_prompt_injection_tests.py
```

实验会覆盖 `results/` 下的同名 CSV。管理令牌从环境变量 `BROKER_ADMIN_TOKEN` 或 `credential-broker/.env` 读取。

## Dashboard

```bash
streamlit run evaluation-dashboard/dashboard/app.py --server.address 0.0.0.0
# http://localhost:8501
```

Dashboard 读取 `results/` 下的 7 份 CSV，分为 issue 测试、verify 测试、凭据生命周期、并发测试、性能测试、撤销竞态、提示注入 7 个 Tab，展示通过率与明细。

也可以通过 Docker Compose 启动：`cd credential-broker/deploy && docker compose --profile dashboard up -d dashboard`。

## 结果字段

每份 CSV 至少包含：

- `case_id`、`category`、`expected_decision`、`actual_decision`；
- `error_code`；
- `credential_accessed`：Broker 是否读取了 Credential；
- `side_effect_count`：上游真实副作用次数；
- `passed`、`timestamp`。

并发、性能、撤销实验另有 `concurrency`、`throughput_rps`、`p50_ms/p95_ms/p99_ms`、`safe` 等字段。完整定义见 [contracts/README.md](contracts/README.md)。

## 复现记录

复现时应记录硬件、操作系统、Go/Python 版本、启动顺序与 CSV 生成时间，并与原结果分目录存放。示例见 [results/reproductions/2026-10-21/README.md](results/reproductions/2026-10-21/README.md)。性能数据与硬件相关，不同机器之间不宜直接比较绝对值。

## 证据边界

- `passed` 由脚本按预期规则计算；
- AA 的 pytest 是协议单元测试，Broker 的 `go test` 是单元与集成测试，本模块是系统实验，三者分别出具证据，不互相替代。

## 相关文档

- [contracts/README.md](contracts/README.md)：CSV 字段定义
- [../docs/threat-model.md](../docs/threat-model.md)：威胁模型
- [../credential-broker/README.md](../credential-broker/README.md#实验支撑接口)：Broker 的实验支撑接口

## ⚠️ 关于撤销竞态测试的预期断言
在 `run_revocation_tests.py` 中，由于 OS 线程调度和网络延迟的不可预测性，我们**不强制断言谁（执行或撤销）先到达终点**。
我们的核心安全断言是 `safe`（即：如果执行成功，底层副作用必须严格等于 1；如果执行被拒，副作用必须严格等于 0）。`expected_decision` 字段记录的是当前测试场景（如强制执行先赢）的理论预期，而 `actual_decision` 是实际发生的线性化顺序。只要 `safe` 为真，即证明系统在并发下未发生数据错乱。
