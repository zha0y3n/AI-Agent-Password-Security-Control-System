#!/bin/sh
# 生成 docker compose 使用的 .env：随机 Vault 主密钥、管理令牌与 Mock Credential。
# .env 已被 gitignore，切勿提交；已存在时不覆盖。
set -eu
cd "$(dirname "$0")"
if [ -e .env ]; then
	echo ".env already exists; delete it first to regenerate" >&2
	exit 1
fi
umask 077
cat >.env <<ENV
BROKER_VAULT_KEY=$(openssl rand -hex 16)
BROKER_ADMIN_TOKEN=$(openssl rand -hex 24)
MOCK_GIT_TOKEN=$(openssl rand -hex 20)
MOCK_DB_TOKEN=$(openssl rand -hex 20)
ENV
echo "wrote $(pwd)/.env"
