# agent-aa

A 模块包含可靠的固定任务 Agent、Authorization Authority、严格协议模型、可信策略、SM2/SM3 封装、Holder Proof、执行回执参考验证、FastAPI 和 CLI。

```bash
pip install -e '.[dev]'
pytest -q
agent-aa demo
```

AA 服务只读取 AA 私钥、公共密钥注册表和可信任务库。`agent-private-key.pem` 仅供本地 `runtime-demo` 模拟独立 Agent，`serve` 不加载它。生产环境应将 Agent 私钥移入独立 Holder Signer/HSM，并替换文件型开发密钥存储。
