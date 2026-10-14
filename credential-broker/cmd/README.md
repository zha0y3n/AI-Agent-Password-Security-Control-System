# Commands

- `broker/`：Credential Broker（可信执行点），配置见 [../README.md](../README.md#配置)。
- `mock-upstream/`：受保护的 Mock Git / Mock DB，需要 `MOCK_GIT_TOKEN` / `MOCK_DB_TOKEN`。

同一个 Docker 镜像包含这两个程序，通过 entrypoint 选择。
