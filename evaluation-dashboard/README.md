# C 模块：安全评测与可视化 (Evaluation Dashboard)

本目录包含针对 A（授权服务）与 B（Broker + Vault）的完整独立攻击测试、并发/性能实验脚本，以及结果可视化 Dashboard。

## 📂 目录结构

- `requirements.txt`：本模块所需的 Python 依赖文件。
- `scripts/`：所有测试与实验执行脚本（含一键启动脚本）。
- `tests/`：pytest 格式的基础单元测试。
- `dashboard/`：Streamlit 可视化面板。
- `contracts/`：跨模块接口与数据格式约定。
- `results/`：已交付的 7 份真实实验数据（CSV），可直接查看。

## 🚀 如何复现测试

**前置条件**：请确保你的机器已安装 `git`、`python3`、`go` 环境。

**步骤 1：获取代码**
```bash
git clone git@github.com:zha0y3n/AI-Agent-Password-Security-Control-System.git
cd AI-Agent-Password-Security-Control-System
```

**步骤 2：一键启动基础服务**
我们提供了一个一键启动脚本。它会自动建 Python 虚拟环境、安装依赖、生成密钥、启动 A 的 AA 服务和 B 的 Broker/Mock 服务，并自动灌入初始数据（Epoch=17）。
请在项目根目录执行：
```bash
bash evaluation-dashboard/scripts/start_all_services.sh
```
*（等待脚本输出 "🎉 环境准备完毕，服务已全部启动！" 即可进行下一步）*

**步骤 3：运行各类实验脚本**
服务启动后，运行以下命令进行测试：
```bash
source .venv/bin/activate

# 1. AA 接口安全测试
python evaluation-dashboard/scripts/run_security_tests.py
sleep 1

# 2. AA 验签接口安全测试
python evaluation-dashboard/scripts/run_verify_tests.py
sleep 1

# 3. 凭据生命周期测试
python evaluation-dashboard/scripts/run_credential_lifecycle_tests.py
sleep 1

# 4. 并发重放测试
python evaluation-dashboard/scripts/run_concurrency_tests.py
sleep 1

# 5. 性能压测
python evaluation-dashboard/scripts/run_performance_tests.py
sleep 1

# 6. 撤销竞态测试
python evaluation-dashboard/scripts/run_revocation_tests.py
sleep 1

# 7. 提示注入越权测试
python evaluation-dashboard/scripts/run_prompt_injection_tests.py
```

## 📊 查看可视化 Dashboard

运行命令启动：
```bash
streamlit run evaluation-dashboard/dashboard/app.py --server.address 0.0.0.0
```
在浏览器中访问 http://localhost:8501 即可查看图表。

## 🛡️ 测试核心理念

C 模块不仅校验 HTTP 状态码，还严格检查底层真实副作用（`side_effects`），确保在任何攻击下，底层业务数据绝未发生越权篡改。
