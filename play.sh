#!/usr/bin/env bash
# Linux: start the private copy (sf-play, from setup.sh) and run the server in this terminal. Ctrl+C stops the server.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
command -v sf-play >/dev/null || { echo "Run setup.sh first."; exit 1; }
sudo -v  # the server needs root for ports 80 and 443; ask now, not in the middle of the server output
(sleep 3 && sf-play) &
# The server binds the ports as root, then drops back to you; no root-owned __pycache__ in the clone either.
exec sudo PYTHONDONTWRITEBYTECODE=1 "$here/.venv/bin/python" "$here/tools/dummy_server.py"
