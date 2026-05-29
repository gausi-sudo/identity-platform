#!/usr/bin/env bash
# Stop the locally-running identity platform.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -f .run/server.pid ] && kill "$(cat .run/server.pid)" 2>/dev/null; then
  echo "→ stopped (pid $(cat .run/server.pid))"
else
  pkill -f "\.run/server" 2>/dev/null && echo "→ stopped" || echo "→ nothing running"
fi
rm -f .run/server.pid
