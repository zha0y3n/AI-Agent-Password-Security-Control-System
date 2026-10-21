# evaluation-dashboard：安全评测与可视化（C）

C 模块负责用**独立实验**证明 A/B 的安全性质，而不是重复 A 的单元测试。当前完整度：**88%**。7 类实验脚本、7 份 CSV 结果和 7 Tab Dashboard 已提交；仍待从干净环境全量复现并补齐证据元数据。

## 目录

```text
scripts/            7 类实验脚本 + 一键启动
tests/              pytest 基础用例（AA 签发接口）
dashboard/          Streamlit Dashboard（读取 7 份 CSV）
contracts/          CSV 字段与跨模块数据约定
results/            已提交的 7 份实验 CSV
requirements.txt    C 的 Python 依赖
```

## 当前结果（2026-10-20）

| 实验 | 文件 | 记录数 | 结果 | 关键结论 |
|---|---|---:|---|---|
| AA 签发攻击 | `results/security.csv` | 10 | 10/10 | 未知任务、换资源、篡改请求等均被拒绝，副作用 0 |
| AA 验签攻击 | `results/verify.csv` | 10 | 10/10 | 签名/绑定/audience 篡改均被拒绝 |
| Credential 生命周期 | `results/credential_lifecycle.csv` | 9 | 9/9 | 创建、重复创建、无 token、轮换/撤销等符合预期 |
| 并发重放 | `results/concurrency.csv` | 15 | 15/15 | 10/50/100/200/500 并发，每轮最大副作用 1 |
| 性能 | `results/performance.csv` | 12 | 12/12 | 1/10/50/100 并发吞吐、P50/P95/P99 |
| 撤销竞态 | `results/revocation.csv` | 50 | 50/50 safe | `execute_allowed` 全为 false，副作用 0 |
| 提示注入 | `results/prompt_injection.csv` | 4 | 4/4 | 任务外资源、篡改请求、伪造 Capability 均被拦截 |

合计 **110 条记录，全部标记通过**。这些是 C 的已提交证据，不等于 A 的 pytest 结果，也不等于已经从零复现的最终结论。

## 复现

前置条件：`git`、`python3`（3.11+）、`go`、`curl`、`openssl`；端口 `8000/8080/9090` 空闲。

```bash
git clone https://github.com/zha0y3n/AI-Agent-Password-Security-Control-System.git
cd AI-Agent-Password-Security-Control-System
bash evaluation-dashboard/scripts/start_all_services.sh
source .venv/bin/activate
```

一键脚本会自动创建 `.venv`、安装 `requirements.txt` 和 A 的开发依赖、生成 `.runtime/` 与 B 的 `.env`、启动 AA/Broker/Mock，并灌入初始数据（`github-prod` 默认对齐 epoch 17）。Docker Compose 不是该脚本的必需项；如需容器化运行，见 B 的 `deploy/`。

运行实验：

```bash
python evaluation-dashboard/scripts/run_security_tests.py
sleep 1
python evaluation-dashboard/scripts/run_verify_tests.py
sleep 1
python evaluation-dashboard/scripts/run_credential_lifecycle_tests.py
sleep 1
python evaluation-dashboard/scripts/run_concurrency_tests.py
sleep 1
python evaluation-dashboard/scripts/run_performance_tests.py
sleep 1
python evaluation-dashboard/scripts/run_revocation_tests.py
sleep 1
python evaluation-dashboard/scripts/run_prompt_injection_tests.py
```

Dashboard：

```bash
streamlit run evaluation-dashboard/dashboard/app.py --server.address 0.0.0.0
# http://localhost:8501
```

## 结果字段

每份 CSV 至少包含：

- `case_id`、`category`、`expected_decision`、`actual_decision`；
- `error_code`；
- `credential_accessed`：是否读取了 Credential；
- `side_effect_count`：上游真实副作用次数；
- `passed`、`timestamp`。

并发、性能、撤销实验另有 `concurrency`、`throughput_rps`、`p50_ms/p95_ms/p99_ms`、`safe` 等字段。完整定义见 [contracts/README.md](contracts/README.md)。

## 已知问题与待办

1. **干净环境复现**：当前 CSV 是已提交证据，仍需从干净环境重跑 7 类实验，并记录硬件、Go/Python 版本、启动顺序、CSV 生成时间。
2. **历史 token 风险**：早期提交曾硬编码 `ADMIN_TOKEN`，当前脚本已改为从环境变量/`.env` 读取；如果该 token 在任何环境使用过，必须轮换。
3. **依赖与端口**：`requirements.txt` 已声明依赖；`start_all_services.sh` 假设 `8000/8080/9090` 空闲。
4. **Dashboard 口径**：7 个 Tab 已能读取 7 份 CSV，最终展示口径和答辩截图仍需 C 确认。
5. **证据边界**：A 的 pytest 只是协议单元测试；C 的 CSV 也不是 A 的测试结果，二者都不能替代干净环境的全系统复现。

## 相关文档

- [contracts/README.md](contracts/README.md)：CSV 字段定义
- [../docs/c-progress.md](../docs/c-progress.md)：C 进度与证据
- [../docs/threat-model.md](../docs/threat-model.md)：威胁模型
- [../credential-broker/README.md](../credential-broker/README.md)：B 的实验支撑接口
