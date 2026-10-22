#!/bin/bash
# 一键准备环境并启动 A、B 服务 (供评委快速复现)

set -e
cd "$(dirname "$0")/../.." # 回到项目根目录

echo "=== 0. 清理可能残留的旧服务 ==="
pkill -f agent-aa || true
pkill -f mock-upstream || true
pkill -f broker || true
pkill -f "go run" || true
sleep 1

echo "=== 1. 检查并创建 Python 虚拟环境 ==="
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "=== 正在安装 Python 依赖 (使用镜像加速，请稍候) ==="
pip install -i https://mirrors.aliyun.com/pypi/simple/ -r evaluation-dashboard/requirements.txt
pip install -i https://mirrors.aliyun.com/pypi/simple/ -e './agent-aa[dev]'

echo "=== 2. 初始化 A 的运行时环境 ==="
rm -rf .runtime # 强制每次重新生成，防止任务过期
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

echo "=== 4. 在后台启动 3 个服务 ==="
source .venv/bin/activate
agent-aa serve --directory .runtime --host 127.0.0.1 --port 8000 > a.log 2>&1 &

cd credential-broker
# 启动前加载密码
set -a; . ./.env; set +a
export GOPROXY=https://goproxy.cn,direct
go run ./cmd/mock-upstream > mock.log 2>&1 &
go run ./cmd/broker > broker.log 2>&1 &
cd ..

echo "=== 等待服务完全就绪 (动态检测端口，带超时) ==="
for i in $(seq 1 30); do
    if curl --max-time 1 -s -o /dev/null http://127.0.0.1:8000/health && \
       curl --max-time 1 -s -o /dev/null http://127.0.0.1:8080/health && \
       curl --max-time 1 -s -o /dev/null http://127.0.0.1:9090/stats; then
        echo "✅ 所有服务已就绪！"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ 错误: 服务启动超时，请检查 a.log, mock.log, broker.log"
        exit 1
    fi
    sleep 1
done

echo "=== 5. 初始化数据 ==="
set -a; . credential-broker/.env; set +a
cd credential-broker
bash scripts/reset.sh
bash scripts/seed.sh
cd ..

echo "==========================================="
echo "🎉 环境准备完毕，服务已全部启动！"
echo "现在请按照 README.md 运行测试脚本。"
echo "==========================================="
