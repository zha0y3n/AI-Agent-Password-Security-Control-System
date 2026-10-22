# 复现记录：2026-10-21

由 B 执行，用于核对 C 已提交的 7 类实验在当前代码上能否复现。上一级目录中 C 原始提交的 CSV 未改动。

## 环境

| 项 | 值 |
|---|---|
| 代码 | `git archive` 导出的提交 `8ec2837`（干净副本，无历史运行状态） |
| 硬件 | AMD Ryzen 9 8945HX，32 线程，15 GiB 内存 |
| 系统 | WSL2，Linux 6.6.87.2-microsoft-standard-WSL2 |
| Go | 1.27.1 |
| Python | 3.13.13（独立 venv：requests 2.34.2、pandas 3.0.6，`agent-aa` 以 editable 方式安装） |
| 生成时间 | 2026-10-21 18:45:21 – 18:45:38（各 CSV 的 `timestamp` 列） |

## 启动顺序

按 `evaluation-dashboard/scripts/start_all_services.sh` 第 2～5 步（未执行第 0 步的 `pkill` 和第 1 步的 pip 镜像安装）：

1. `agent-aa init-demo --directory .runtime`
2. 由 `.env.example` 生成 `credential-broker/.env`（随机 Vault 主密钥与管理令牌，`MOCK_*_TOKEN` 为脚本期望的固定值，`BROKER_ENABLE_RESET=1`）
3. 启动 AA `:8000`、Mock `:9090`、Broker `:8080`（Go 二进制由同一副本构建）
4. `scripts/reset.sh`、`scripts/seed.sh`
5. 依次运行 `run_{security,verify,credential_lifecycle,concurrency,performance,revocation,prompt_injection}_tests.py`

## 结果

| 实验 | 本次 | C 原始提交 |
|---|---:|---:|
| AA 签发攻击 | 10/10 | 10/10 |
| AA 验签攻击 | 10/10 | 10/10 |
| Credential 生命周期 | 9/9 | 9/9 |
| 并发重放（10～500） | 15/15 | 15/15 |
| 性能 | 12/12 | 12/12 |
| 撤销竞态 | 50/50 safe | 50/50 safe |
| 提示注入 | 4/4 | 4/4 |

共 110/110。

## 观察

- 撤销竞态两次运行都是 50 轮全部 `DENY`（49 次 `CREDENTIAL_INACTIVE`、1 次 `CREDENTIAL_EPOCH_MISMATCH`），即撤销总是先于执行线性化，“执行先赢”的分支没有被覆盖。A+B 的 `scripts/e2e-lifecycle.py` 用随机抖动让两种顺序都出现（50 轮中 35 轮先执行、15 轮先撤销），并用审计链顺序核对“上游被调用 ⇒ consume 在 revoke 之前”。C 的脚本如需覆盖该分支，可以在撤销前加入同样的抖动。
- 性能数据是本机单次运行，与 C 原始数据不在同一台机器上，不宜直接比较绝对值。
