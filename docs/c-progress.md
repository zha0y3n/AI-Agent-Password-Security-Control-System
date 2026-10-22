# C 模块进度

更新时间：2026-10-22（Asia/Shanghai）。完整度：**88%**。

## 已完成

| 实验 | 脚本 | 结果文件 | 记录数 | 结果 |
|---|---|---|---:|---|
| AA 签发攻击 | `run_security_tests.py` | `security.csv` | 10 | 10/10 |
| AA 验签攻击 | `run_verify_tests.py` | `verify.csv` | 10 | 10/10 |
| Credential 生命周期 | `run_credential_lifecycle_tests.py` | `credential_lifecycle.csv` | 9 | 9/9 |
| 并发重放 | `run_concurrency_tests.py` | `concurrency.csv` | 15 | 15/15 |
| 性能 | `run_performance_tests.py` | `performance.csv` | 12 | 12/12 |
| 撤销竞态 | `run_revocation_tests.py` | `revocation.csv` | 50 | 50/50 safe |
| 提示注入 | `run_prompt_injection_tests.py` | `prompt_injection.csv` | 4 | 4/4 |

关键结论：

- 并发实验覆盖 10/50/100/200/500，每轮真实副作用最多 1 次；
- 撤销实验 50 轮全部满足“未读 Credential、无副作用、执行被拒”；
- 提示注入与 AA 签发攻击的拒绝路径副作用均为 0；
- Dashboard 已能读取 7 份 CSV，提供 7 个 Tab。

## 验证边界

- CSV 记录时间集中在 2026-10-20；它们是已提交证据，但尚未由 C 从干净环境重新复现；
- 复现时必须记录硬件、Go/Python 版本、启动顺序、CSV 生成时间；
- A 的 pytest 只是协议单元测试，不能替代 C 的系统实验；
- 历史提交曾出现硬编码 `ADMIN_TOKEN`；当前脚本已改为从环境变量/`.env` 读取，如该 token 在任何环境使用过必须轮换。

## 待办

1. ~~干净环境全量复现 7 类实验~~：2026-10-21 由 B 在 `git archive` 导出的干净副本上复现，110/110，元数据见 `evaluation-dashboard/results/reproductions/2026-10-21/README.md`；答辩前仍建议在目标机器上再跑一次；
2. 答辩材料；`revocation.csv` 没有覆盖“执行先赢”的分支，可在撤销前加入随机抖动（参考 `scripts/e2e-lifecycle.py`）；
3. 确认 Dashboard 展示口径和截图；
4. 确认 `requirements.txt`、端口和 `start_all_services.sh` 在目标机器可用；
5. `result_envelope` 与统一错误码表已固化（`shared/README.md`、`docs/error-codes.md`）；CSV 的 `error_code` 直接取 `decision.code`，无需改动。

## 相关文档

- [../evaluation-dashboard/README.md](../evaluation-dashboard/README.md)
- [../evaluation-dashboard/contracts/README.md](../evaluation-dashboard/contracts/README.md)
- [threat-model.md](threat-model.md)
