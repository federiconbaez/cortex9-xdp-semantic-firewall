# LIMITES — #4 Firewall semántico XDP

Esto es lo que **no** hace, para que nadie lo venda como otra cosa.

| Pedido original | Estado | Por qué |
|---|---|---|
| Inspeccionar payloads gRPC/MCP en tránsito | **Parcial**: solo en claro | XDP ve paquetes antes de la pila; no tiene claves TLS. Con TLS solo se ven metadatos (IPs, puertos, tamaños, tiempos). |
| A velocidad de placa | **No medido** | Probado en `xdpgeneric` sobre `lo`. Modo driver (`--native`) existe en el código pero no se probó: `enp0s4` es virtio en una VM y no se midió throughput. |
| Detectar inyección de prompts | **Heurístico** | Kernel: 8 literales ≤32 B en los primeros 256 B. Usuario: reglas con normalización. Una paráfrasis nueva pasa. |
| Anomalías del grafo de llamadas | **Mínimo** | Máquina de estados MCP por flujo TCP. No correlaciona entre flujos, ni entre agentes, ni aprende. |
| Cortar conexiones | **Sí, por descarte** | Se descartan los segmentos del flujo; no se envía RST (eso requeriría construir un paquete con XDP_TX o usar TC). |
| MCP por stdio | **Fuera de alcance** | No pasa por la red. Haría falta otra técnica (p. ej. un proxy de stdio o uprobes sobre read/write). |
| HTTP/2 / gRPC con HPACK, frames partidos | **No** | No hay reensamblado TCP en XDP. Un literal partido entre dos segmentos no coincide. |

## Errores reales encontrados y corregidos durante el desarrollo
1. Verificador: `R4 invalid zero-sized read` en `bpf_xdp_load_bytes`. El
   compilador perdía la cota inferior de la longitud. Se fuerza `n ∈ [1,256]`.
2. Verificador: `BPF program is too large` (1M instrucciones). El bucle de
   8 patrones × 32 bytes dentro del callback explotaba los estados. Se aplanó
   a `bpf_loop(n * 8, …)` (un patrón por iteración) con el bucle interno sin
   desenrollar. Resultado: carga con 3976 B traducidos.
3. Demo: el grafo de llamadas leía también las respuestas del servidor (el eco
   del fixture) y marcaba `ReInitialize` en una sesión legítima. Corregido:
   el grafo solo lee pedidos (puerto destino vigilado); la capa semántica sí
   mira ambas direcciones (la salida de una herramienta puede traer inyección).

4. Demo: carrera en la capa de usuario. A veces el bloqueo desde usuario llega
   antes del eco del 1.er segmento y lo corta también. Es timing real, no un
   error: el fixture ya no exige el resultado del 1.er segmento en esos casos.

## Attach
Último attach: OK en `lo`, modo `xdpgeneric`, kernel 6.12.94+, con `sudo -n`.
No hubo fallos de attach que registrar.

## Medido en el experimento de valor (21/10/2026, ver VALOR.md)
- Con un sobre JSON-RPC normal, los argumentos de `tools/call` empiezan después
  del byte ~200: la capa semántica (192 B) **no los ve**. Actuó 0 veces en 2270
  sesiones. Con cabeceras reales de MCP streamable HTTP (263 B) tampoco se ve `method`.
- Bug: si el nombre de la herramienta queda cortado en el byte 192, el grafo con
  lista blanca da `ToolNotAllowed("")` y corta sesiones legítimas (7,7–12,3 % de
  los benignos).
