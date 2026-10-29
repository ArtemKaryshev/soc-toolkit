#!/usr/bin/env bash
# Запуск SOC Toolkit на Linux/macOS: первый запуск создаёт окружение и ставит зависимости.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -e .
fi
exec .venv/bin/soc-toolkit ui "$@"
