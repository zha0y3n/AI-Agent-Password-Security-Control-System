# Commands

- `broker/`：Credential Broker（可信执行点），默认监听 `:8080`；配置见 [../README.md](../README.md#配置)。
- `mock-upstream/`：受保护的 Mock Git / Mock DB，默认监听 `:9090`；需要 `MOCK_GIT_TOKEN` / `MOCK_DB_TOKEN`。

同一个 Docker 镜像包含这两个程序，通过 entrypoint 选择。Broker 只应暴露给 Agent 和受控管理端；Mock 上游在生产环境应只接受来自 Broker 的连接（mTLS 或网络策略）。
