#!/usr/bin/env bash
# Demo real: XDP en `lo` (xdpgeneric) + fixture TCP en claro. Requiere sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-18080}
cargo build --quiet
BIN=target/debug/fnbr-xdp-fw
LOG=$(mktemp)
sudo -n "$BIN" run --iface lo --ports "$PORT" --seconds 20 >"$LOG" 2>&1 &
LPID=$!
for _ in $(seq 50); do grep -q "XDP adjuntado" "$LOG" && break; sleep 0.1; done
grep -q "XDP adjuntado" "$LOG" || { cat "$LOG"; echo "ATTACH FALLÓ"; exit 1; }
set +e
python3 scripts/fixture.py "$PORT"; RC=$?
set -e
sudo -n kill -INT "$LPID" 2>/dev/null || true
wait "$LPID" 2>/dev/null || true
echo "----- log del cargador -----"; cat "$LOG"; rm -f "$LOG"
ip link show lo | grep -q xdp && { echo "ERROR: XDP quedó adjuntado"; exit 1; }
echo "XDP desadjuntado correctamente."
exit $RC
