# Evaluation contract

每份实验 CSV 都必须能回答三个问题：

1. 预期决策是什么、实际决策是什么；
2. 是否读取了 Credential；
3. 上游真实副作用发生了多少次。

不能只看 HTTP 状态码。

## 公共字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `case_id` | string | 用例唯一标识 |
| `category` | string | 攻击/实验类别 |
| `expected_decision` | `ALLOW` / `DENY` | 预期决策 |
| `actual_decision` | `ALLOW` / `DENY` | 实际决策 |
| `error_code` | string | 拒绝码；成功时为空 |
| `credential_accessed` | bool | Broker 是否读取/解密了 Credential |
| `side_effect_count` | int | Mock 上游真实副作用次数 |
| `passed` | bool | 本用例是否通过 |
| `timestamp` | ISO-8601 | 记录生成时间 |

## 按实验的附加字段

### `security.csv` / `verify.csv` / `credential_lifecycle.csv`

| 字段 | 含义 |
|---|---|
| `description` | 用例说明 |
| `expected_http` | 预期 HTTP 状态 |
| `actual_http` | 实际 HTTP 状态 |
| `latency_ms` | 客户端观测延迟 |

### `concurrency.csv`

| 字段 | 含义 |
|---|---|
| `concurrency` | 并发数（10/50/100/200/500） |
| `round` | 轮次 |
| `total_requests` | 总请求数 |
| `success_count` | 成功执行数 |
| `replay_reject_count` | 因 Challenge/重放被拒绝数 |
| `other_count` | 其他结果数 |
| `duration_s` | 本轮耗时 |
| `side_effect_count` | 本轮真实副作用次数；必须 ≤ 1 |

### `performance.csv`

| 字段 | 含义 |
|---|---|
| `concurrency` | 并发数（1/10/50/100） |
| `round` | 轮次 |
| `total_requests` | 总请求数 |
| `total_s` | 总耗时 |
| `throughput_rps` | 吞吐量 |
| `p50_ms` / `p95_ms` / `p99_ms` | 延迟分位 |
| `min_ms` / `max_ms` | 最小/最大延迟 |

### `revocation.csv`

| 字段 | 含义 |
|---|---|
| `round` | 轮次（默认 50 轮） |
| `execute_http` | 执行接口 HTTP 状态 |
| `execute_allowed` | 执行是否被允许；竞态安全时应为 false |
| `execute_error` | 执行拒绝码 |
| `revoke_http` | 撤销接口 HTTP 状态 |
| `safe` | 本轮是否满足“未读 Credential、无副作用、执行被拒” |

### `prompt_injection.csv`

| 字段 | 含义 |
|---|---|
| `description` | 注入/越权场景说明 |
| `detail` | 补充证据或原始错误 |

## 与 Broker 接口的映射

| C 字段 | 来源 |
|---|---|
| `actual_decision` / `error_code` | `/v1/execute` 的 `decision.allowed` / `decision.code` |
| `credential_accessed` | `/v1/execute` 的 `credential_loaded` |
| `side_effect_count` | Mock `GET /stats` 的副作用计数 |
| 最终 Capability 状态 | `GET /v1/capabilities/{id}`（管理员） |
| Receipt 证据 | `/v1/execute` 响应中的 `receipt`，用 `/v1/broker/key-registry` 验签 |
| 审计证据 | `/v1/audit`、`/v1/audit/checkpoints`、`/v1/audit/verify` |
| `latency_ms` | 客户端自测或 `/v1/metrics` |

## 边界

- `passed` 是脚本根据预期规则计算的结果，不是独立第三方结论；
- 复现结果应与原结果分目录存放，并记录运行环境；
- AA 的 pytest 结果不能当作系统实验结论。
