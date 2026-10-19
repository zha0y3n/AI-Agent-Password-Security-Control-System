#!/bin/bash
# 一键启动 A、B 服务并初始化环境 (供评委快速复现使用)

set -e
cd "$(dirname "$0")/../.." # 回到项目根目录

echo "=== 1. 检查并创建 Python 虚拟环境 ==="
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r evaluation-dashboard/requirements.txt
pip install -q -e './agent-aa[dev]'

echo "=== 2. 初始化 A 的运行时环境 ==="
if [ ! -d ".runtime" ]; then
    agent-aa init-demo --directory .runtime
fi

echo "=== 3. 配置 B 的 .env 文件 ==="
cd credential-broker
if [ ! -f ".env" ]; then
    cp .env.example .env
    VAULT_KEY=$(openssl rand -hex 16)
    ADMIN_TOKEN=$(openssl rand -hex 24)
    sed -i "s/^BROKER_VAULT_KEY=.*/BROKER_VAULT_KEY=$VAULT_KEY/" .env
    sed -i "s/^BROKER_ADMIN_TOKEN=.*/BROKER_ADMIN_TOKEN=$ADMIN_TOKEN/" .env
    sed -i "s/^MOCK_GIT_TOKEN=.*/MOCK_GIT_TOKEN=mock-git-secret/" .env
    sed -i "s/^MOCK_DB_TOKEN=.*/MOCK_DB_TOKEN=mock-db-secret/" .env
    sed -i "s/^BROKER_TRUSTED_ISSUER=.*/BROKER_TRUSTED_ISSUER=aa-demo-01/" .env
    sed -i "s|^BROKER_KEY_REGISTRY=.*|BROKER_KEY_REGISTRY=../.runtime/public-keys.json|" .env
    sed -i "s/^BROKER_ENABLE_RESET=.*/BROKER_ENABLE_RESET=1/" .env
    echo "已生成新的 .env 配置"
fi
cd ..

echo "=== 4. 在后台启动 3 个服务 (日志将输出到项目根目录下的 log 文件) ==="
source .venv/bin/activate
agent-aa serve --directory .runtime --host 127.0.0.1 --port 8000 > a.log 2>&1 &
echo "A 服务已启动 (PID: $!)"

cd credential-broker
set -a; . ./.env; set +a
go run ./cmd/mock-upstream > mock.log 2>&1 &
echo "Mock 服务已启动 (PID: $!)"

go run ./cmd/broker > broker.log 2>&1 &
echo "Broker 服务已启动 (PID: $!)"

cd ..

echo "=== 等待 3 秒让服务完全就绪 ==="
sleep 3

echo "=== 5. 初始化数据 ==="
set -a; . credential-broker/.env; set +a
cd credential-broker
bash scripts/reset.sh
bash scripts/seed.sh
cd ..

echo "==========================================="
echo "✅ 所有服务已启动并完成数据初始化！"
echo "现在你可以直接运行实验脚本，例如："
echo "  python evaluation-dashboard/scripts/run_concurrency_tests.py"
echo "==========================================="
