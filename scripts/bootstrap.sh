#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_dir="${repo_dir}/.venv"

python3 -m venv "${venv_dir}"
"${venv_dir}/bin/python" -m pip install --upgrade pip
"${venv_dir}/bin/pip" install -e "${repo_dir}/agent-aa[dev]"
"${venv_dir}/bin/pytest" "${repo_dir}/agent-aa/tests" -q
