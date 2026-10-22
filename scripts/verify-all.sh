#!/usr/bin/env bash
# 一键验证：单元测试 → 跨语言互操作 → 真实进程的 A+B 生命周期联调 →（可选）Docker Compose 全链路。
#
# 用法：
#   bash scripts/bootstrap.sh            # 首次：创建 .venv 并安装 agent-aa
#   bash scripts/verify-all.sh           # 前四步，约 1 分钟
#   bash scripts/verify-all.sh --compose # 另加 Docker Compose 全链路（需要 Docker，首次构建较慢；占用 8000/8080/9090）
#
# 联调步骤使用临时目录里的运行时、数据库和随机密钥，监听随机空闲端口，结束后全部删除；
# 不读写仓库里的 .runtime/、credential-broker/.env 或 data/，也不会结束本机其他进程。
set -uo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="${repo_dir}/.venv/bin/python"
with_compose=0
for arg in "$@"; do
  case "${arg}" in
    --compose) with_compose=1 ;;
    -h | --help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

results=()
failed=0
record() { # record <name> <exit code>
  if [[ "$2" -eq 0 ]]; then results+=("PASS  $1"); else results+=("FAIL  $1"); failed=1; fi
}
section() { printf '\n==== %s ====\n' "$1"; }

section "0. 前置条件"
missing=()
for tool in go curl openssl; do command -v "${tool}" >/dev/null || missing+=("${tool}"); done
[[ -x "${python}" ]] || missing+=(".venv（先运行 bash scripts/bootstrap.sh）")
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "缺少：${missing[*]}" >&2
  exit 2
fi
echo "go: $(go version | cut -d' ' -f3)  python: $("${python}" -c 'import sys; print(sys.version.split()[0])')"

section "1. Broker 单元测试（go vet + go test -race）"
(cd "${repo_dir}/credential-broker" && go vet ./... && go test -race -count=1 ./...)
record "Broker 单元测试" $?

section "2. A 单元测试（pytest）"
"${repo_dir}/.venv/bin/pytest" "${repo_dir}/agent-aa/tests" -q
record "A 单元测试" $?

section "3. 跨语言互操作（make interop）"
(cd "${repo_dir}/credential-broker" && make --no-print-directory interop PYTHON="${python}")
record "跨语言互操作" $?

section "4. A+B 生命周期联调（真实 Broker + Mock 进程）"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

lifecycle() {
  # 在子 shell 中运行：导出的密钥不外泄，退出（含失败）时结束本步启动的 Broker / Mock
  # pids 不能是 local：EXIT trap 在函数返回后才执行，那时局部变量已经失效
  pids=()
  trap 'kill "${pids[@]}" 2>/dev/null; wait 2>/dev/null' EXIT
  local broker_port mock_port
  read -r broker_port mock_port < <("${python}" -c '
import socket
socks = [socket.socket() for _ in range(2)]
for s in socks: s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))
for s in socks: s.close()')
  "${repo_dir}/.venv/bin/agent-aa" init-demo --directory "${work}/runtime" >/dev/null || return 1
  (cd "${repo_dir}/credential-broker" && go build -o "${work}/bin/" ./cmd/broker ./cmd/mock-upstream) || return 1

  export BROKER_VAULT_KEY="$(openssl rand -hex 16)" BROKER_ADMIN_TOKEN="$(openssl rand -hex 24)"
  export MOCK_GIT_TOKEN="$(openssl rand -hex 16)" MOCK_DB_TOKEN="$(openssl rand -hex 16)"
  export BROKER_ADDR="127.0.0.1:${broker_port}" MOCK_ADDR="127.0.0.1:${mock_port}"
  export BROKER_UPSTREAM_URL="http://127.0.0.1:${mock_port}"
  export BROKER_DB_PATH="${work}/data/broker.db" BROKER_SIGNING_KEY_FILE="${work}/data/receipt.key"
  export BROKER_CHECKPOINT_KEY_FILE="${work}/data/checkpoint.key"
  export BROKER_TRUSTED_ISSUER=aa-demo-01 BROKER_KEY_REGISTRY="${work}/runtime/public-keys.json"
  export BROKER_ENABLE_RESET=1
  mkdir -p "${work}/data"

  "${work}/bin/mock-upstream" >"${work}/mock.log" 2>&1 &
  pids+=($!)
  "${work}/bin/broker" >"${work}/broker.log" 2>&1 &
  pids+=($!)
  local i
  for i in $(seq 1 50); do
    curl -sf "http://127.0.0.1:${broker_port}/health" >/dev/null &&
      curl -sf "http://127.0.0.1:${mock_port}/health" >/dev/null && break
    sleep 0.2
  done
  if [[ ${i} -eq 50 ]]; then
    echo "Broker / Mock 未能启动：" >&2
    tail -n 5 "${work}/broker.log" "${work}/mock.log" >&2
    return 1
  fi
  "${python}" "${repo_dir}/scripts/e2e-lifecycle.py" --reset --runtime "${work}/runtime" \
    --broker "http://127.0.0.1:${broker_port}" --mock "http://127.0.0.1:${mock_port}" || return 1

  # 日志中不得出现任何密钥或 Credential
  if grep -qF -e "${BROKER_VAULT_KEY}" -e "${BROKER_ADMIN_TOKEN}" -e "${MOCK_GIT_TOKEN}" -e "${MOCK_DB_TOKEN}" \
    "${work}/broker.log" "${work}/mock.log"; then
    echo "Broker / Mock 日志中出现了密钥或 Credential" >&2
    return 1
  fi
  echo "日志中未出现 Vault 主密钥、管理令牌或 Credential"
}
(lifecycle)
record "A+B 生命周期联调" $?

if [[ ${with_compose} -eq 1 ]]; then
  section "5. Docker Compose 全链路"
  compose() {
    command -v docker >/dev/null || { echo "未安装 Docker" >&2; return 1; }
    # 在临时副本里运行，生成的 .env 与卷不会留在仓库中
    local copy="${work}/compose" project="acgverify$$"
    mkdir -p "${copy}"
    git -C "${repo_dir}" ls-files -z | (cd "${repo_dir}" && xargs -0 tar -cf - --) | tar -xf - -C "${copy}" || return 1
    cd "${copy}/credential-broker/deploy" || return 1
    sh gen-env.sh >/dev/null || return 1
    local status=0
    # up 会依次启动 aa-init → aa / mock → broker → seed；等 seed 写完种子 Credential 再跑 e2e
    docker compose -p "${project}" up -d --build && docker compose -p "${project}" wait seed >/dev/null &&
      docker compose -p "${project}" run --rm e2e || status=1
    docker compose -p "${project}" down -v --remove-orphans >/dev/null 2>&1
    return ${status}
  }
  (compose)
  record "Docker Compose 全链路" $?
fi

section "汇总"
printf '%s\n' "${results[@]}"
if [[ ${failed} -ne 0 ]]; then
  echo "存在失败的步骤。" >&2
  exit 1
fi
echo "全部通过。"
