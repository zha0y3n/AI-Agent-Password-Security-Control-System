# Broker API

完整接口、`POST /v1/execute` 的请求/响应、错误码与 HTTP 状态、Receipt 与 `result_envelope` 提案见 [../README.md](../README.md#http-接口)。

与 A 的生命周期联动：

- `GET /v1/credentials/{credential_id}/status` 返回非秘密元数据（`credential_id`、`provider`、`status`、`credential_epoch`、`created_at`、`updated_at`）；
- A 的 `BROKER_LIVE` 使用该端点获取实时 epoch，字段与 `shared/schemas/credential-status.schema.json` 一致；
- A 的预检查不替代 Broker 在执行事务内的 `ACTIVE + epoch` 原子检查；
- `result_envelope` 结构与 Receipt 返回方式仍待 A/C 联审，固化后写入 `shared/schemas/`。
