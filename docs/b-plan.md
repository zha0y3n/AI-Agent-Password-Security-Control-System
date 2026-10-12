# 成员 B 项目进行计划：Trusted Execution Domain / Go

> 定位：负责“这张使用权现在能不能兑现”。
> 排序原则：**先做不依赖 A / C 的部分**，再接入 A 的协议交付物，最后面向 C 输出证据和实验支撑。
> 协议细节（字段名、签名输入、编码格式）一律以 A 的 `shared/` 与 `docs/crypto-protocol.md`、`docs/a-b-interface.md` 为准。

---

## 0. 技术选型

| 项 | 选择 | 理由 |
|---|---|---|
| 语言 | Go 1.27 | 本机已安装 |
| HTTP | 标准库 `net/http` | 路由已支持方法与路径参数，无需框架 |
| 国密 | `github.com/emmansun/gmsm` | SM2 / SM3 / SM4 齐全，SM4 可直接接 `cipher.NewGCM` |
| 数据库 | SQLite + `modernc.org/sqlite` | 纯 Go、免 cgo，Docker 构建简单 |
| 测试 | `go test` + `-race` | 并发 / 竞态必须跑 race detector |

工程目录：`credential-broker/`（沿用 A 搭好的目录）。

---

## 阶段一：不依赖 A / C，立即开工

这一阶段只用国密标准、Broker 自己的密钥和自己定义的数据结构，A 的代码是否到位都不影响。

### 1.1 工程骨架

- `go.mod`、`cmd/broker/main.go`、配置加载（监听地址、DB 路径、Vault 主密钥、Broker 密钥路径，全部来自环境变量 / 文件）
- `GET /health`
- 统一 JSON 响应与错误响应结构（错误码先用占位，阶段二与 A 统一）
- **日志脱敏**：日志层禁止输出 Credential、密钥、明文结果中的敏感字段；提供脱敏测试
- `Makefile` / `scripts`：`build`、`test`、`test-race`、`run`

验收：`go build ./...`、`go test ./...` 通过，`/health` 返回 200。

### 1.2 国密基础封装（`internal/crypto/`）

- SM3：封装 + **国标测试向量**（如 `"abc"`、64 字节重复串）
- SM4-GCM：封装加解密 + AAD；测试篡改密文 / Tag / AAD 均解密失败
- SM2：Broker 自身密钥生成、加载、签名、验签（用于 Receipt / Checkpoint）
  - 签名编码、公钥编码、SM2 ID 先做成可配置，阶段二按 `crypto-protocol.md` 定死

验收：国标向量通过；篡改类测试全部失败。

### 1.3 数据层（`internal/repository/`）

- SQLite 打开参数：WAL、`busy_timeout`、外键开启
- 建表（迁移脚本）：
  - `credentials`：id、provider、status、epoch、ciphertext、nonce、created_at、updated_at
  - `capabilities`：cap_id、state、request_hash、credential_id、credential_epoch、consumed_at、result
  - `challenges`：challenge、agent_id、expires_at、used
  - `executions`：cap_id、request_hash、result_hash、receipt
  - `audit_log`：seq、entry、prev_hash、hash
  - `checkpoints`：seq、head_hash、signature
- 事务封装：所有状态转换走单事务

验收：迁移可重复执行；事务回滚测试通过。

### 1.4 Credential Vault（`internal/vault/`）

- SM4-GCM 加密存储长期 Credential
- AAD = `credential_id ‖ provider ‖ credential_epoch`（拼接格式写进文档）
- Vault 主密钥 `K_V` 只从环境变量 / 密钥文件加载，不入库、不入日志
- 解密只暴露给执行层内部调用，用后尽量清零缓冲区
- **Credential 明文不出现在任何 API 响应中**

验收：换 epoch / 换 id 后旧密文解密失败；明文不出现在响应与日志（测试断言）。

### 1.5 Credential 生命周期与 Epoch（`internal/credential/`）

- 状态：`ACTIVE` / `DISABLED` / `REVOKED` / `COMPROMISED` / `DESTROYED`
- 操作：Create、Rotate、Disable、Re-enable、Revoke、Mark Compromised、Destroy
- **每次状态变更 epoch++**；Rotate 时用新 epoch 重新加密
- 管理接口（内部 / 管理员用）：`POST /v1/credentials`、`POST /v1/credentials/{id}/{action}`
- 只读接口：`GET /v1/credentials/{id}/status`（返回 status + epoch，不含密文）——供 AA 获取当前 Epoch，阶段二与 A 确认

验收：Disable → Re-enable 后 epoch 已变化，旧 epoch 不再匹配；Destroy 后不可恢复。

### 1.6 Atomic Consume（`internal/capability/`）

- 状态机：`ISSUED → CONSUMING → CONSUMED`，失败分支 `CONSUMING → FAILED`
- CAS 实现：`UPDATE capabilities SET state='CONSUMING' WHERE cap_id=? AND state='ISSUED'`，以受影响行数判断胜负
- 首次见到的 cap_id 先插入 `ISSUED`（`INSERT OR IGNORE`），再 CAS
- **线性化点**：同一事务内完成“Credential status/epoch 检查 + CAS”，与 Revoke 的 epoch++ 由 SQLite 写锁串行化
- 用伪造的 cap_id 测试即可，不需要真实 Capability

验收：100 goroutine 并发消费同一 cap_id，**成功恰好 1 个**（`go test -race`）；Revoke 与 Consume 并发时不会出现“旧 epoch 消费成功”。

### 1.7 Idempotency

- `idempotency_key = cap_id`，保存 `request_hash + result`
- 同 cap + 同 request_hash → 返回已存结果，不再产生副作用
- 同 cap + 不同 request_hash → DENY

验收：两种情况各有测试。

### 1.8 Mock 业务服务（`internal/upstream/`）

- Mock Git API：`read_file`、`write_file` 等少量操作
- Mock DB API：`query`、`update`
- **要求携带 Credential 才能调用**（校验 Credential 正确）
- **副作用计数器**：按 cap_id / 资源统计实际执行次数，提供查询接口给 C 用
- 可选择内嵌在 Broker 进程，或独立端口启动

验收：无 / 错 Credential 调用失败；计数器准确。

### 1.9 审计链与 Checkpoint（`internal/evidence/`）

- `H_i = SM3(H_{i-1} ‖ L_i)`，`L_i` 用 Canonical 编码（阶段二换成与 A 一致的实现）
- 每 N 条或定时生成 Checkpoint：`SM2.Sign(sk_B, SM3(seq ‖ H_head))`
- 导出接口：`GET /v1/audit`、`GET /v1/audit/checkpoints`、`GET /v1/broker/public-key`
- 编写 `docs/audit-chain.md`，写清字节格式，供 C 独立验证

验收：修改 / 删除 / 回滚任一条目，Go 自带校验函数能检出。

### 1.10 校验流水线框架（`internal/verifier/`）

- 定义 `Step` 接口与有序 `Pipeline`，输出 `Decision{Allow/Deny, Reason, ErrorCode, FailedStep}`
- **任何一步失败立即停止，且保证未读取 Vault、未调用上游**（用计数器断言）
- 各步骤先放空实现 / 桩，阶段二逐一填入

验收：桩步骤失败时 Vault 读取次数 = 0、上游调用次数 = 0。

### 1.11 Broker Challenge 机制

- 生成随机 challenge（CSPRNG）、绑定 agent_id、设置 TTL、单次使用（消费也走 CAS）
- `POST /v1/challenge`
- 字段名、长度、编码阶段二按 A 的规范调整

验收：过期 / 重复使用 / 他人 challenge 均被拒绝。

### 1.12 性能埋点与容器化

- 每个阶段计时：Capability Verify、Holder Verify、Request Hash、Credential Decrypt、Atomic Consume、Upstream、Total
- 通过响应头或 `/v1/metrics` 暴露，方便 C 采集
- `Dockerfile`（多阶段构建，非 root 运行）

---

## 阶段二：接入 A 的协议交付物

**前置条件：A 把代码推到 GitHub。**

### 2.1 先对齐的问题

- [ ] SM2 签名编码：DER 还是 `r‖s`
- [ ] SM2 公钥编码：`04‖X‖Y` hex / base64 / PEM
- [ ] SM2 ID：是否为默认 `1234567812345678`
- [ ] 签名输入：对 Canonical 字节签（含 Z 值预处理），还是对 SM3 摘要签
- [ ] Holder Proof 签名输入的精确字节拼接
- [ ] Broker Challenge 的格式、TTL、下发与消费方式
- [ ] AA 获取 Credential Epoch 的方式（建议使用 1.5 的只读接口）
- [ ] 统一错误码表
- [ ] Receipt 的返回方式（随 `/v1/execute` 响应一起返回 / 单独查询）

### 2.2 实现

- Go Canonical JSON：严格按 `docs/crypto-protocol.md`，**通过 Canonical Bytes 向量**
- Request Hash：**通过 SM3 Request Hash 向量**
- **先用 Go 验证 `shared/test-vectors/sm2-sm3-v1.json` 中的三组向量：Capability / Holder Proof / Execution Receipt**
- 按 `shared/schemas/execution-bundle.schema.json` 严格解析（拒绝未知字段、类型错误）
- 填充流水线步骤，顺序按 `docs/a-b-interface.md`：
  - Schema → Capability 签名 → Audience → Expiration → Holder Proof + Challenge
  - → Task / Service / Resource / Operation → Request Hash
  - → Credential Status == ACTIVE 且 Epoch 相等 → Atomic Consume
- 按 `signed-receipt.schema.json` 与 A 的签名规范签发 Receipt，**Python 侧 `receipt.py` 能验过**
- 统一错误码
- `POST /v1/execute` 完整串联：校验 → Consume → Vault 解密 → Mock API → Receipt → Audit

验收：每个 Vector 的篡改版本 Go 验证均失败。

---

## 阶段三：A + B 联调

- 跑通：Agent → AA → Capability → Challenge → Holder Proof → Broker → Vault → Mock API → Receipt → Audit
- 用 A 提供的攻击样例逐条验证 DENY：篡改、过期、跨任务、错误资源、Wrong Holder、RequestHash 不一致、Audience 错误、旧 Epoch、重放
- 确认 Agent 日志、Prompt、API 响应、普通日志中都没有 Credential 明文
- 发现协议分歧：A + B 共同确认后，重新生成 `shared/schemas/` 与 `shared/test-vectors/`

---

## 阶段四：面向 C 的证据与实验支撑

- 确认 C 可用的接口：副作用计数器、Audit 导出、Checkpoint、Broker 公钥、Metrics
- 并发 Replay、Revocation Race 测试的环境支撑（批量创建 Credential / 重置状态）
- `scripts/reset` + 种子数据：每次实验从干净状态开始
- `docker-compose.yml`：AA + Broker + Mock 服务 (+ Dashboard)
- 在全新环境执行 `git clone` + `docker compose up`，跑通全部 Demo 场景

---

## 阶段五：竞赛化

- 文档：Broker 架构、Verification Pipeline、Atomic Consume 语义（为什么不是 Strict Exactly Once）、Vault 设计、Audit Chain、部署说明
- 答辩准备：
  - Broker 为什么是可信执行点？
  - Credential 什么时候出现明文？
  - 为什么 Agent 绕不过 Broker？
  - Atomic Consume 如何实现？
  - 为什么不是 Strict Exactly Once？
  - Receipt 为什么必须由 Broker 生成？
- 只修 Bug，不改协议

---

## 依赖一览

| 工作项 | 依赖 A | 依赖 C |
|---|---|---|
| 1.1 – 1.12 | 否（1.11 字段格式后续微调） | 否 |
| 2.x 协议接入 | **是**：spec + 测试向量 | 否 |
| 3.x 联调 | **是**：AA 服务 | 否 |
| 4.x 证据 / 实验 | 否 | **是**：接口需求 |
