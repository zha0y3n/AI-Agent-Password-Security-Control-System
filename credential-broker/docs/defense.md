# 答辩材料（Broker / B）

> 每题先给 30 秒内能说完的结论，再给展开要点和代码位置。细节见 [architecture.md](architecture.md) 和 [security-mapping.md](security-mapping.md)。

## 一、计划中的六个必答题

### 1. Broker 为什么是可信执行点？

**结论：** 它是系统里唯一同时具备三样东西的进程：长期 Credential、Credential 和 Capability 的实时状态、通往受保护服务的执行通道。

- AA 能签名，但没有 Credential，也不知道 Capability 用没用过。Agent 什么都不可信。上游服务不了解 Capability 协议。
- 所以“这张使用权现在能不能兑现”只能由 Broker 回答：是不是原持有者、请求有没有被换、Credential 有没有被撤销、是不是第一次用。
- Broker 的判断依据全部来自本地配置和本地状态。audience、可信 AA、公钥表都不取自请求（`internal/verifier/steps.go` 的 `Config`）。

### 2. Credential 什么时候出现明文？

**结论：** 只在 Broker 进程内，只在三个地方，而且一律发生在所有校验和原子消费之后。

1. 管理员录入或轮换时：请求体解码后立即加密。
2. 生命周期变更时：迁移到新 epoch，解密后立即重新加密并清零。
3. 执行时：`Credentials.Open` → 放进上游请求的 `Authorization` 头 → 调用返回后 `Wipe()`。

补充说明：

- 任何拒绝都发生在 `Open` 之前，这是代码结构保证的。测试断言了拒绝路径上 Vault 解密次数和上游调用次数都不变。
- `secret.Secret` 类型打印、写日志、序列化 JSON 时都输出 `[REDACTED]`。
- **主动承认的局限：** Go 字符串副本和 HTTP 库内部缓冲无法主动清零。防御能读进程内存的攻击者需要 HSM 或机密计算，不在本项目的信任假设内。

### 3. 为什么 Agent 绕不过 Broker？

**结论：** Agent 手里没有能直接调用上游的东西，也伪造不出 Broker 会接受的东西。

- **直接调上游**：没有 Credential，返回 401。Mock 会统计 `auth_failures`，C 可以拿这个计数作为证据。
- **伪造 Capability**：需要 AA 的 SM2 私钥。
- **偷别人的 Capability**：需要原 Agent 的 Holder 私钥，而且 Holder Proof 要绑定 Broker 刚发出的 Challenge。
- **拿合法 Capability 干别的事**：Broker 自己重算请求摘要。路径、资源、操作、body 改一个字节，摘要就对不上。
- **部署前提**：上游只接受来自 Broker 的连接，这一条靠网络隔离保证。Demo 中 Mock 绑定 127.0.0.1，生产环境应使用 mTLS 或网络策略。

### 4. Atomic Consume 如何实现？

**结论：** 在一个 SQLite `BEGIN IMMEDIATE` 事务里，先检查 Credential 是否 ACTIVE、epoch 是否一致，再执行 CAS `ISSUED → CONSUMING`，以受影响行数判定胜负。

- `BEGIN IMMEDIATE` 一开始就拿写锁，所以 Consume、Revoke、Rotate 严格串行。这一刻就是线性化点（`internal/capability/consume.go`）。
- 并发 100 次只有 1 个赢家。撤销与消费的竞态 40 轮全部可线性化，用审计序号核对先后。全部测试都在 `-race` 下运行。
- 赢家执行完写回 `CONSUMED`，并保存结果和回执。之后的重放只返回原结果，不再调用上游。
- **为什么 Challenge 和 Capability 各有一个状态机：**
  - Challenge 防止“同一份 Proof 再交一次”。
  - Capability 状态防止“同一张票换个 Challenge 再用一次”。

### 5. 为什么不是严格的 exactly-once？

**结论：** 外部 API 和 Broker 的数据库不在同一个事务里，崩溃总能落在两者之间。我们保证的是**至多一次副作用 + 成功结果可幂等重放**。

- CAS 之后、调用之前崩溃：上游没执行，票作废，需要重新签发。
- 调用之后、写回之前崩溃：上游执行了一次，Broker 没有记录，票停在 `CONSUMING`，不会再执行。
- 上游超时：不知道对方是否执行，记为 `FAILED`，不重试。

三种情况都满足“至多一次”，代价是可能“零次”，这是安全优先于可用的取舍。

要补成“恰好一次”，需要上游配合实现幂等。我们每次调用都带 `X-Idempotency-Key = capability_id`，Mock 已经实现了去重，将来的恢复流程可以安全地重试。

### 6. Receipt 为什么必须由 Broker 生成？

**结论：** 只有 Broker 知道实际发生了什么。

- AA 签发时请求还没执行；Agent 不可信；上游不了解 Capability 协议。
- 回执用 Broker 的 SM2 密钥签名，签名域是 `EXECUTION_RECEIPT`，不能和 Capability、Holder Proof 的签名互换。
- `result_hash = SM3(规范化的 result_envelope)`，绑定 capability_id、request_hash、outcome 和上游响应。
- A 的 `ReceiptVerifier` 用 Broker 发布的公钥记录就能独立验证，不需要信任 Broker 的 HTTP 响应本身。
- 拒绝也签回执（DENIED），但只为 AA 签名验过的 Capability 签，Broker 不为伪造的 ID 背书。

## 二、可能的追问

**Q：为什么用 SQLite，不怕性能问题？**
单机 Demo 下，SQLite 的单写锁正好提供了最简单、最容易证明的线性化点。换成 PostgreSQL 时，语义可以用 `SELECT … FOR UPDATE` 加同一事务的 CAS 保留下来。吞吐数据以 C 的性能实验为准。

**Q：校验步骤为什么是这个顺序？**
三条原则：

1. 先验 AA 签名，才相信 Capability 里的字段。
2. Broker 先自己重算请求摘要，再拿它去验 Holder Proof。
3. 所有不写状态的检查放在消费 Challenge 之前，坏请求不会烧掉 Challenge。

Credential 检查必须和 CAS 在同一事务内，所以不放在流水线里。

**Q：Epoch 有什么用？只看状态不行吗？**
只看状态，Disable 之后再 Enable，旧票会复活；Rotate 之后，旧票会拿着新 Credential 去执行。每次状态变更都让 epoch 加一，Capability 签的是具体的 epoch，所以任何变更都让旧票永久失效。Vault 的 AAD 也绑定 epoch，在数据层再兜一次底。

**Q：时钟不同步怎么办？**
`issued_at` 允许 5 秒偏差（与 A 的参考实现一致，可通过 `BROKER_CLOCK_SKEW` 配置）。`expires_at` 不放宽。Demo 中 Capability 的有效期是 60 秒（A 的默认值），Challenge 也是 60 秒，偏差窗口相对很小。

**Q：Broker 自己的签名私钥泄露怎么办？**
攻击者可以伪造回执和检查点，但仍然拿不到 Credential（需要 `K_V`），也伪造不了 Capability（需要 AA 私钥）。处置方式是换新的 Broker 密钥和 `BROKER_KEY_ID`，并通知验证方不再信任旧公钥。已知限制有两条：当前公钥记录接口只发布当前密钥，不能把旧密钥标记为 REVOKED；换密钥需要重启 Broker。

**Q：DENIED 回执会不会被用来做 DoS？**
只有 AA 签名验过的请求才会触发签名，攻击者至少要先拿到一张合法的 Capability。拿到之后，配上一份无效的 Holder Proof 反复提交，每次会让 Broker 多做一次 SM2 签名。这时一次拒绝的代价是一次验签加一次签名，大约是普通拒绝的两倍，属于常数级放大。缓解办法是按 Agent 或 Capability 限流，或者把 DENIED 回执改成按需签发。具体开销以 C 的压测结果为准。

**Q：怎么证明你们的 Go 实现和 A 的 Python 实现一致？**

- `shared/test-vectors` 里的规范字节、请求摘要、三组 SM2 签名向量，Go 逐字节一致；篡改后的版本全部验签失败。
- `make interop`：A 签发、Go 执行、Go 签回执、A 验证。
- `e2e-demo.py` 在真实 HTTP 上跑一遍完整流程。

**Q：如何防止 Broker 运维人员篡改审计？**
SM3 哈希链能检测修改、删除和重排，SM2 签名检查点能检测回滚和截断。局限是：能拿到 Broker 私钥的运维可以重写整条链。生产环境应把检查点定期外送到独立存储，或使用透明日志。

## 三、演示流程（约 5 分钟）

准备工作（提前做好）：

```bash
cd credential-broker/deploy
sh gen-env.sh                      # 生成本地密钥到 .env（已 gitignore）
docker compose up -d --build       # AA + Broker + Mock，seed 自动执行
docker compose --profile tools run --rm reset   # 确保从干净状态开始
```

| 步骤 | 操作 | 要讲的点 |
|---|---|---|
| 1 | `docker compose --profile tools run --rm e2e` | 14 项检查逐条打印 PASS |
| 2 | 指着“正常执行”一段 | Agent 只拿到结果和回执；回执由 A 的验证器、用 Broker 公布的公钥验过 |
| 3 | 指着“攻击样例”一段 | 重放、篡改请求、篡改 Capability、偷票、伪造 Challenge 各自停在哪一步，拒绝码是什么 |
| 4 | 指着“证据”一段 | **上游只被调用了 1 次**：所有攻击都在读取 Credential 之前被拒绝；审计链复核通过 |
| 5 | `curl -s 127.0.0.1:8080/v1/audit/verify` | 审计链可以独立复核；C 用 `docs/audit-chain.md` 也能自己验 |
| 6 | 轮换 `github-prod` 后重跑 e2e（可选） | 旧 epoch 的票立即失效（`CREDENTIAL_EPOCH_MISMATCH`），而且 DENIED 回执同样可以验证 |
| 7 | `docker compose logs broker mock aa \| grep -c "$MOCK_GIT_TOKEN"`（先 `set -a; . ./.env; set +a`） | 输出 0：日志里找不到 Credential 的值 |

步骤 6 的操作：

```bash
set -a; . ./.env; set +a
curl -s -X POST -H "Authorization: Bearer $BROKER_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"secret\":\"$MOCK_GIT_TOKEN\"}" 127.0.0.1:8080/v1/credentials/github-prod/rotate
docker compose --profile tools run --rm e2e    # 预期：正常执行被拒（CREDENTIAL_EPOCH_MISMATCH），脚本以非零状态退出
docker compose --profile tools run --rm reset  # 演示后恢复
```

> 注意：步骤 6 会把管理员令牌和 Mock Credential 展开在命令行参数里，同一台机器的其他用户可以从进程列表中看到。现场演示时请使用临时生成的 `.env`，演示后删除，并重新运行 `gen-env.sh`。
