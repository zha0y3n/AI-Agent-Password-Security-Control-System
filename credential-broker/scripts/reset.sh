#!/bin/sh
# 让 Broker 与 Mock 上游回到干净状态，然后重新播种（seed.sh）。仅用于开发 / 实验环境。
#
# Broker 需以 BROKER_ENABLE_RESET=1 启动。清空内容：Credential、Capability、Challenge、
# 审计链与检查点、性能指标；Mock 恢复种子仓库 / 数据库并清零副作用统计。
# Broker 的 SM2 签名密钥不变，因此之前公布的公钥记录仍然有效。
#
# 环境变量同 seed.sh，另有：
#   MOCK_URL  默认 http://127.0.0.1:9090
#   SEED      设为 0 时只重置、不播种
set -eu

BROKER_URL=${BROKER_URL:-http://127.0.0.1:8080}
MOCK_URL=${MOCK_URL:-http://127.0.0.1:9090}
: "${BROKER_ADMIN_TOKEN:?BROKER_ADMIN_TOKEN is required}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077
printf 'Authorization: Bearer %s\n' "$BROKER_ADMIN_TOKEN" >"$tmp/hdr"

code=$(curl -sS -o "$tmp/out" -w '%{http_code}' -X POST -H "@$tmp/hdr" "$BROKER_URL/v1/admin/reset")
[ "$code" = 200 ] || { echo "reset: broker refused: $code $(cat "$tmp/out")" >&2; exit 1; }
echo "reset: broker state cleared"
curl -fsS -o /dev/null -X POST "$MOCK_URL/reset"
echo "reset: mock upstream restored"

if [ "${SEED:-1}" != 0 ]; then
	exec sh "$(dirname "$0")/seed.sh"
fi
