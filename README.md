# 面向 AI Agent 的密码凭据零接触使用与生命周期联动安全控制系统

本仓库是按《111》分工建立的 Monorepo。当前第一轮交付聚焦 A：Python Agent + Authorization Authority（AA），实现固定任务、可信授权、SM2/SM3 Capability、Holder Proof、执行回执规范和跨语言测试向量。B 的 Broker/Vault 与 C 的评测/Dashboard 目前只有协作骨架，不能视为全系统完成。

## 目录

```text
agent-aa/                A：可运行的 Agent + AA
credential-broker/       B：Go Broker/Vault 骨架与接口入口
evaluation-dashboard/    C：评测/Dashboard 骨架与样例约定
shared/                  JSON Schema、协议输入、跨语言向量
docs/                    进度、威胁模型、协议与交接文档
scripts/                 安装、测试、启动和产物生成脚本
参考/                    原始项目资料
```

## 环境与安装

要求 Python 3.11+。密码原语使用铜锁 `tongsuopy==1.0.1`，不包含自研 SM2/SM3/SM4 实现。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/pip install -e './agent-aa[dev]'
```

若默认 PyPI 镜像不可达，可显式指定可用镜像，例如：

```bash
.venv/bin/pip install -i https://mirrors.aliyun.com/pypi/simple -e './agent-aa[dev]'
```

也可运行：

```bash
bash scripts/bootstrap.sh
```

## 运行测试和闭环演示

```bash
.venv/bin/pytest agent-aa/tests -q
.venv/bin/agent-aa demo
```

`demo` 在内存中生成临时 AA/Agent SM2 密钥，完成：

```text
固定任务 → 确定性 AgentRequest → AA 策略检查 → Signed Capability
       → Broker Challenge → Holder Proof → Python 参考验签
```

演示中不会生成或向 Agent 提供目标业务 Credential。

## 启动 AA FastAPI

先生成 gitignored 的开发运行目录；密钥随机生成，不在源码中硬编码：

```bash
.venv/bin/agent-aa init-demo --directory .runtime
.venv/bin/agent-aa runtime-demo --directory .runtime
.venv/bin/agent-aa serve --directory .runtime --host 127.0.0.1 --port 8000
```

程序会尝试把私钥文件设为 `0600`。Windows/WSL 挂载盘可能仍报告 `0777`，此时 CLI 会告警；该目录只能用于本机演示，正式密钥必须放在能执行访问控制的 Linux 文件系统、Secret Manager 或 HSM/独立签名器中。

另一个终端检查：

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/v1/public-keys/aa-key-demo-01
```

签发接口为 `POST /v1/capabilities/issue`。请求体只接受 `AgentRequest + ttl_seconds`；可信 `TaskContext` 从 AA 本地任务库读取，客户端不能提交一份自称可信的上下文要求 AA 签名。接口详情见 [docs/a-b-interface.md](docs/a-b-interface.md)。

## 当前边界

- 已完成的是 A 端第 1～6 周期核心交付及 Python 参考校验器。
- B 尚需实现 Credential 状态/epoch 实时检查、Challenge 存储与一次性消费、原子 Capability 消费、Vault、受保护 API 调用、真实回执签发和审计。
- C 尚需实现独立攻击脚本、并发/撤销/性能实验、CSV 和 Dashboard。
- Python 测试通过不代表 Broker/Vault 或全链路安全性质已经通过。

详见 [docs/a-progress.md](docs/a-progress.md) 与 [docs/a-manual-review.md](docs/a-manual-review.md)。
