#!/usr/bin/env bash
# Run the identity platform locally (backend API on http://127.0.0.1:8000).
#
# Uses an embedded SQLite database that is reset to a clean state on every
# start, so local runs are deterministic. No external database required.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PORT="${PORT:-8000}"
export driverName="${driverName:-sqlite}"
export dataSourceName="${dataSourceName:-file:./data/local.db?cache=shared}"

# Stop anything already running, then reset state for a clean start.
if [ -f .run/server.pid ]; then kill "$(cat .run/server.pid)" 2>/dev/null || true; fi
pkill -f "\.run/server" 2>/dev/null || true
rm -rf data
mkdir -p data .run

echo "→ building server (first run compiles dependencies; later runs are fast)…"
go build -o .run/server .

echo "→ starting on http://127.0.0.1:${PORT} (fresh database)…"
.run/server > .run/server.log 2>&1 &
echo $! > .run/server.pid

if curl --retry 120 --retry-delay 1 --retry-connrefused -s -o /dev/null "http://127.0.0.1:${PORT}/api/get-account"; then
  echo "→ ready: http://127.0.0.1:${PORT}  (API base: http://127.0.0.1:${PORT}/api)"
else
  echo "✗ server did not become ready — see .run/server.log" >&2
  exit 1
fi
