#!/bin/sh
# 向 Broker 录入实验用 Credential（种子数据）。只依赖 POSIX sh + curl，可在 curl 容器中运行。
#
# 必填环境变量：
#   BROKER_ADMIN_TOKEN  Broker 管理令牌
#   MOCK_GIT_TOKEN      Mock Git 期望的 Credential（录入为 github-prod）
#   MOCK_DB_TOKEN       Mock DB 期望的 Credential（录入为 db-prod）
# 可选：
#   BROKER_URL          默认 http://127.0.0.1:8080
#   SEED_GIT_EPOCH      github-prod 的目标 epoch，默认 17（与 A 可信任务库中写死的值对齐）
#   SEED_BATCH          额外创建 batch-0001..N（provider=github，Credential 同 MOCK_GIT_TOKEN），供并发 / 撤销实验，默认 0
#
# 已存在的 Credential 不会被覆盖：脚本只打印其状态。需要干净状态请先运行 reset.sh。
set -eu

BROKER_URL=${BROKER_URL:-http://127.0.0.1:8080}
SEED_GIT_EPOCH=${SEED_GIT_EPOCH:-17}
SEED_BATCH=${SEED_BATCH:-0}
: "${BROKER_ADMIN_TOKEN:?BROKER_ADMIN_TOKEN is required}"
: "${MOCK_GIT_TOKEN:?MOCK_GIT_TOKEN is required}"
: "${MOCK_DB_TOKEN:?MOCK_DB_TOKEN is required}"

# Credential 会被拼进 JSON，只接受不需要转义的字符。
for v in "$MOCK_GIT_TOKEN" "$MOCK_DB_TOKEN"; do
	case $v in *[!A-Za-z0-9._-]*) echo "seed: tokens may only contain [A-Za-z0-9._-]" >&2; exit 1 ;; esac
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077
# 令牌经文件传给 curl，不出现在进程参数里。
printf 'Authorization: Bearer %s\n' "$BROKER_ADMIN_TOKEN" >"$tmp/hdr"

# api METHOD PATH [JSON]：输出 HTTP 状态码，响应体写入 $tmp/out。
api() {
	if [ $# -ge 3 ]; then
		printf '%s' "$3" | curl -sS -o "$tmp/out" -w '%{http_code}' -X "$1" -H "@$tmp/hdr" \
			-H 'Content-Type: application/json' --data-binary @- "$BROKER_URL$2"
	else
		curl -sS -o "$tmp/out" -w '%{http_code}' -X "$1" -H "@$tmp/hdr" "$BROKER_URL$2"
	fi
}

i=0
until curl -fsS -o /dev/null "$BROKER_URL/health"; do
	i=$((i + 1))
	[ "$i" -lt 30 ] || { echo "seed: broker at $BROKER_URL is not healthy" >&2; exit 1; }
	sleep 1
done

# seed ID PROVIDER SECRET EPOCH：创建并轮换到目标 epoch（每次 Rotate 使 epoch+1）。
seed() {
	code=$(api GET "/v1/credentials/$1/status")
	if [ "$code" = 200 ]; then
		echo "seed: $1 exists: $(cat "$tmp/out")"
		return
	fi
	code=$(api POST /v1/credentials "{\"credential_id\":\"$1\",\"provider\":\"$2\",\"secret\":\"$3\"}")
	[ "$code" = 201 ] || { echo "seed: create $1 failed: $code $(cat "$tmp/out")" >&2; exit 1; }
	e=1
	while [ "$e" -lt "$4" ]; do
		code=$(api POST "/v1/credentials/$1/rotate" "{\"secret\":\"$3\"}")
		[ "$code" = 200 ] || { echo "seed: rotate $1 failed: $code $(cat "$tmp/out")" >&2; exit 1; }
		e=$((e + 1))
	done
	echo "seed: created $1 (provider=$2, epoch=$4)"
}

seed github-prod github "$MOCK_GIT_TOKEN" "$SEED_GIT_EPOCH"
seed db-prod db "$MOCK_DB_TOKEN" 1
n=1
while [ "$n" -le "$SEED_BATCH" ]; do
	seed "$(printf 'batch-%04d' "$n")" github "$MOCK_GIT_TOKEN" 1
	n=$((n + 1))
done
