#!/usr/bin/env bash
# Experimento de VALOR del #4: ¿el firewall semántico XDP bloquea tráfico MCP de
# ataque que una línea base ESTÁTICA no ve, sin falsos positivos?
# Requiere sudo -n (XDP en lo + nftables). Solo toca `lo` y el puerto $PORT.
# Uso: bash scripts/experimento-valor.sh [semillas...]   (por defecto 1 2 3 4 5)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
V=experimentos/valor
PORT=${PORT:-18181}
NLAT=${NLAT:-2000}
SEEDS=("${@:-1 2 3 4 5}"); read -r -a SEEDS <<<"${SEEDS[*]}"
ALLOW=weather,search,read_file,list_dir,create_issue,translate,summarize,calendar_list
OUT=$V/resultados/crudo
BIN=target/release/fnbr-xdp-fw
SINK_PID=""; FW_PID=""

limpiar() {
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  [ -n "$FW_PID" ] && sudo -n kill -INT "$FW_PID" 2>/dev/null || true
  sleep 0.5
  sudo -n nft delete table inet fnbr_valor 2>/dev/null || true
  if ip link show lo | grep -q xdp; then sudo -n ip link set dev lo xdpgeneric off; fi
}
trap limpiar EXIT

sudo -n nft --version >/dev/null 2>&1 || { echo "falta nft (apt-get install nftables)"; exit 1; }
cargo build --release --quiet
if ip link show lo | grep -q xdp; then echo "lo ya tiene XDP adjuntado: no sigo"; exit 1; fi
if sudo -n nft list table inet fnbr_valor >/dev/null 2>&1; then echo "tabla fnbr_valor ya existe: no sigo"; exit 1; fi
rm -rf "$OUT"; mkdir -p "$OUT"
python3 $V/baseline.py nft $V/palabras_clave.txt "$PORT" 241 >"$OUT/baseline.nft"

sink_up() { python3 $V/sink.py "$PORT" "$1" >/dev/null 2>&1 & SINK_PID=$!; sleep 0.4; }
sink_down() { kill "$SINK_PID" 2>/dev/null || true; wait "$SINK_PID" 2>/dev/null || true; SINK_PID=""; }

cfg_up() {
  case $1 in
    sin_filtro) ;;
    nft) sudo -n nft -f "$OUT/baseline.nft" ;;
    xdp)
      sudo -n "$ROOT/$BIN" run --iface lo --ports "$PORT" --allow-tools "$ALLOW" >"$2" 2>&1 & FW_PID=$!
      for _ in $(seq 100); do grep -q "XDP adjuntado" "$2" && break; sleep 0.1; done
      grep -q "XDP adjuntado" "$2" || { cat "$2"; echo "ATTACH FALLÓ"; exit 1; } ;;
  esac
}
cfg_down() {
  case $1 in
    nft) sudo -n nft list table inet fnbr_valor >"$2"; sudo -n nft delete table inet fnbr_valor ;;
    xdp) sleep 0.3; sudo -n kill -INT "$FW_PID"; wait "$FW_PID" 2>/dev/null || true; FW_PID=""
         if ip link show lo | grep -q xdp; then echo "ERROR: XDP quedó adjuntado"; exit 1; fi ;;
  esac
}

base=20000
for s in "${SEEDS[@]}"; do
  python3 $V/generar_corpus.py --seed "$s" --out $V/corpus/seed-$s.jsonl >/dev/null
  C=$V/corpus/seed-$s.jsonl
  for perfil in minimo streamable; do
    for cfg in sin_filtro nft xdp; do
      tag=s$s-$perfil-$cfg
      sink_up "$OUT/$tag.sink.jsonl"
      cfg_up $cfg "$OUT/$tag.fw.log"
      python3 $V/replay.py --corpus "$C" --port "$PORT" --perfil $perfil --modo detectar \
        --base-puerto $base --out "$OUT/$tag.replay.jsonl"
      cfg_down $cfg "$OUT/$tag.fw.log"
      sink_down
      base=$((base + 800)); [ $base -gt 64000 ] && base=20000
      echo "[ok] $tag"
    done
  done
  for cfg in sin_filtro nft xdp; do
    tag=s$s-lat-$cfg
    sink_up "$OUT/$tag.sink.jsonl"
    cfg_up $cfg "$OUT/$tag.fw.log"
    python3 $V/replay.py --corpus "$C" --port "$PORT" --perfil minimo --modo latencia --n "$NLAT" \
      --base-puerto $base --out "$OUT/$tag.lat.json"
    cfg_down $cfg "$OUT/$tag.fw.log"
    sink_down
    base=$((base + 50))
    echo "[ok] $tag"
  done
done
limpiar; trap - EXIT
echo "limpieza: XDP en lo = $(ip link show lo | grep -c xdp || true) ; tabla nft fnbr_valor = $(sudo -n nft list tables | grep -c fnbr_valor || true)"
python3 $V/analizar.py --dir "$OUT" --seeds "${SEEDS[@]}" --palabras $V/palabras_clave.txt --port "$PORT" \
  --out $V/resultados/resumen
tar -C $V/resultados -cJf $V/resultados/crudo.tar.xz crudo
echo "resumen: $V/resultados/resumen.md ; crudo: $V/resultados/crudo.tar.xz"
