#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_dir="${repo_dir}/.runtime"

if [[ ! -f "${runtime_dir}/config.json" ]]; then
  "${repo_dir}/.venv/bin/agent-aa" init-demo --directory "${runtime_dir}"
fi
exec "${repo_dir}/.venv/bin/agent-aa" serve --directory "${runtime_dir}" --host 127.0.0.1 --port 8000
