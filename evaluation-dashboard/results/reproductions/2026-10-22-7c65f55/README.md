# 复现记录：2026-10-22（提交 7c65f55）

由 B 执行，在当前代码上复现 C 的 8 类实验，覆盖读取 `credential_loaded` 的新判定和 70 轮撤销竞态。上一级 `results/` 中 C 提交的 CSV 未改动。

## 环境

| 项 | 值 |
|---|---|
| 代码 | `git archive` 导出的提交 `7c65f55`（干净副本，无历史运行状态） |
| 硬件 | AMD Ryzen 9 8945HX，32 线程，15 GiB 内存 |
| 系统 | WSL2，Linux 6.6.87.2-microsoft-standard-WSL2 |
| Go | 1.27.1（Broker 与 Mock 由同一副本 `go build`） |
| Python | 3.13.13（独立 venv：requests 2.34.2、pandas 3.0.6、tongsuopy 1.0.1，`agent-aa` 以 editable 方式安装） |
| 生成时间 | 2026-10-22 01:27:02 – 01:27:44（UTC-7，各 CSV 的 `timestamp` 列） |

## 启动顺序

按 `evaluation-dashboard/scripts/start_all_services.sh` 第 2～5 步（未执行第 0 步的 `pkill` 和第 1 步的 pip 镜像安装）：

1. 删除并重新生成 `.runtime`（`agent-aa init-demo`）
2. 由 `.env.example` 生成 `credential-broker/.env`（随机 Vault 主密钥与管理令牌，`MOCK_*_TOKEN` 为脚本期望的固定值，`BROKER_ENABLE_RESET=1`）
3. 启动 AA `:8000`、Mock `:9090`、Broker `:8080`
4. `scripts/reset.sh`、`scripts/seed.sh`
5. 依次运行 `run_{security,verify,credential_lifecycle,concurrency,performance,revocation,prompt_injection,broker_full_attack}_tests.py`

## 结果

| 实验 | 结果 | 备注 |
|---|---:|---|
| AA 签发攻击 | 10/10 | |
| AA 验签攻击 | 10/10 | |
| Credential 生命周期 | 9/9 | |
| 并发重放（10～500） | 15/15 | 每轮成功 1、解密 1、副作用 1；500 并发三轮 0.703 / 0.696 / 0.712 s |
| 性能 | 12/12 | 每轮 100 个请求全部放行且解密，Mock 副作用均为 100 |
| 撤销竞态 | 70/70 safe | `execute_first` 25 轮全部 ALLOW；`revoke_first` 25 轮全部 DENY；`random_race` 20 轮中 ALLOW 8、DENY 12 |
| 提示注入 | 4/4 | 均未解密 Credential，副作用 0 |
| Broker 全链路攻击 | 7/7 | 仅正常请求解密 1 次；6 类攻击均未解密，副作用 0 |

共 137/137。所有 ALLOW 记录的 `credential_accessed` 为 true 且副作用为 1，所有 DENY 记录均为 false 且副作用为 0。

性能（3 轮均值）：

| 并发 | 吞吐（req/s） | P50（ms） | P95（ms） | P99（ms） |
|---:|---:|---:|---:|---:|
| 1 | 161.82 | 2.29 | 3.06 | 4.24 |
| 10 | 206.48 | 8.63 | 15.56 | 23.15 |
| 50 | 227.98 | 24.61 | 43.71 | 51.34 |
| 100 | 241.67 | 26.30 | 42.11 | 51.76 |

Dashboard 用 `streamlit.testing.v1.AppTest` 以本目录 CSV 无界面渲染：8 个 Tab，无异常、无缺失文件告警。

## 观察

- 撤销竞态的 `passed` 等于 `safe`，`expected_decision` 按实际结果回填，见 `evaluation-dashboard/README.md`“撤销竞态的判定”。`execute_first` 是顺序操作，真正的竞态样本是 `random_race` 的 20 轮。
- 性能数据是本机单次运行，与其他机器上的结果不宜直接比较绝对值。
