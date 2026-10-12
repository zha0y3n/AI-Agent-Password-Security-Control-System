#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${repo_dir}/.venv/bin/pytest" "${repo_dir}/agent-aa/tests" -q
