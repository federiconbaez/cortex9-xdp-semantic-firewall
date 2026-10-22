# 04 — Firewall semántico XDP (eBPF)

> **ES:** Firewall semántico XDP (eBPF + Rust/aya) que inspecciona payloads MCP/gRPC en el kernel. Compilar/probar: `make && cargo test`.
> **EN:** XDP semantic firewall (eBPF + Rust/aya) inspecting MCP/gRPC payloads in-kernel. Build/test: `make && cargo test`.
>
> **Estado / Status (AUDIT-valor.md, commit auditado `43ffd0b`):** **FALLA el umbral #4 / FAILS threshold #4 — «valor no demostrado» / value not demonstrated.** XDP bloqueó 5,1–7,7 % de los ataques vs 41,9–47,4 % de un filtro de string emulado (pierde por ataques) y su FPR (9,1–16,8 %) supera la tolerancia frente a nftables (falla por FPR). Hay además un bug conocido en el byte 192, hallazgo aparte. Licencia / License: MIT OR Apache-2.0 (el programa eBPF en `bpf/` es GPL-2.0, ver README.md / the eBPF program in `bpf/` is GPL-2.0, see README.md).


**Dueña:** בֶּן הָאֱלֹהִים הַחַי (rol de auditoría de seguridad)
**Pedido de Federico (20/10/2026):** firewall semántico en el plano de datos XDP
que inspeccione payloads gRPC/MCP en tránsito a velocidad de placa y corte
conexiones ante patrones de inyección de prompts o anomalías del grafo de llamadas.

## Qué hace de verdad (v0.1)

Dos capas, una en el kernel y otra en espacio de usuario:

```
 paquete ──► XDP (kernel, bpf/xdp_firewall.bpf.c)
             1. Eth → IPv4 → TCP. Solo puertos en `watch_ports`.
             2. ¿Flujo en `blocked`? → XDP_DROP.
             3. Copia ≤256 B del payload en claro y busca (sin mayúsculas)
                hasta 8 patrones literales con bpf_loop.
             4. Coincidencia → bloquea el flujo (ambas direcciones) + XDP_DROP.
             5. Siempre manda ≤192 B del prefijo al ring buffer `events`.
                │
                ▼
 fnbr-xdp-fw (Rust + aya, espacio de usuario)
             · semantic.rs: normaliza (leetspeak, separadores, acentos,
               ancho cero, tokens de rol) y puntúa. ≥10 = bloquear.
             · callgraph.rs: máquina de estados MCP por flujo (tools/call antes
               de initialize, método desconocido, herramienta fuera de lista
               blanca, re-initialize).
             · Si alguna dice "bloquear" → escribe el flujo en `blocked` y el
               kernel descarta los siguientes segmentos.
```

"Cortar la conexión" = descartar todos los segmentos siguientes del flujo en
XDP (incluidas retransmisiones). **No se envía RST**: la conexión queda colgada
hasta que el cliente hace timeout.

## Límites honestos (detalle en `LIMITES.md`)
- **No ve TLS.** Si MCP/gRPC va cifrado, XDP solo ve bytes cifrados. Este
  firewall sirve para tráfico **en claro** (HTTP/1.1 local, h2c sin
  compresión de cabeceras relevante, gRPC sin TLS en loopback).
- **MCP por stdio no pasa por la red.** Ese tráfico nunca llega a XDP.
- **No rearma TCP ni HTTP/2.** Una frase partida entre dos segmentos, o más
  allá de los primeros 256 B (kernel) / 192 B (usuario), no se ve.
- **La capa semántica reacciona tarde.** El primer segmento con inyección
  ofuscada **pasa**; se cortan los siguientes. Solo los patrones literales
  se cortan antes de llegar.
- Las heurísticas son reglas, no un modelo. Hay falsos negativos seguros
  (paráfrasis) y falsos positivos posibles (textos que *hablan* de inyección).
- "Velocidad de placa": no medido. Se probó en modo `xdpgeneric` sobre `lo`,
  que pasa por la pila de red y **no** es el camino rápido del driver.

## Valor contra línea base
Ver `VALOR.md` (21/10/2026): contra una lista estática no demuestra valor en
inyección; solo detecta, tarde, anomalías de protocolo MCP. La capa semántica
no llega a ver los argumentos (192 B). Reproducir: `bash scripts/experimento-valor.sh`.

## Requisitos
Linux con XDP, `clang`, `libbpf-dev` (headers), Rust ≥ 1.85, `sudo` para la demo.
En la computadora compartida todo eso está instalado (kernel 6.12.94+).

## Compilar y probar
```bash
cd /workspace/sistemas/04-xdp-semantic-firewall
cargo build            # build.rs compila el BPF con clang -target bpf
cargo test             # 19 tests, sin root
cargo clippy --all-targets -- -D warnings
bash scripts/demo.sh   # con sudo: XDP real en lo + fixture TCP en claro
cargo run -- classify "1gn0r3 pr3v10us 1nstruct10ns"   # probar el clasificador
```

Uso real (root): `sudo target/debug/fnbr-xdp-fw run --iface enp0s4 --ports 8080,50051 --allow-tools weather,search`

## Criterio de verificado
Ver `VERIFICADO.md`. Evidencia de la última corrida en `evidencia/demo-2026-10-20.txt`.
