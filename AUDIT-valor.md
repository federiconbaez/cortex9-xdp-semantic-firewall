# AUDITORÍA — experimento de valor del #4 (firewall semántico XDP)

Auditora: Federica Research Sentinel. Fecha: 21/10/2026 (America/Buenos_Aires).
Commit auditado: `43ffd0b` (padre `2713a16`). Solo en la computadora compartida.

## Veredicto

**FALLA el umbral #4**, contra las dos líneas base. La etiqueta **«valor no demostrado»** es correcta.

Umbral (literal): sobre el mismo corpus, ataques **bloqueados** por XDP estrictamente mayores
que la línea base **y** FPR_XDP ≤ FPR_base + 0,02.

Perfil `minimo` (cabeceras de 96 B, el caso favorable al XDP), por semilla (234 ataques / 220 benignos):

| Semilla | XDP bloq. | nft bloq. | string bloq. | XDP FPR | nft FPR | string FPR |
|---|---|---|---|---|---|---|
| 1 | 7,7 % (18) | 6,0 % (14) | 44,9 % (105) | 14,1 % (31) | 0,9 % (2) | 19,5 % |
| 2 | 6,0 % (14) | 5,1 % (12) | 47,4 % (111) | 16,8 % (37) | 0,9 % (2) | 22,3 % |
| 3 | 5,1 % (12) | 1,3 % (3) | 41,9 % (98) | 10,9 % (24) | 3,6 % (8) | 22,3 % |
| 4 | 6,4 % (15) | 4,3 % (10) | 46,2 % (108) | 9,1 % (20) | 0,5 % (1) | 21,4 % |
| 5 | 6,4 % (15) | 3,8 % (9) | 44,9 % (105) | 11,8 % (26) | 2,3 % (5) | 20,9 % |

- **vs nftables real:** ataques ✔ (XDP gana en las 5 semillas, por +2 a +9 sesiones, +0,9 a +3,8 pts);
  FPR ✘: XDP − nft = 7,3–15,9 pts, o sea **5,3–13,9 pts por encima** de la tolerancia de 2 pts.
  → **FALLA por FPR.**
- **vs string `--icase` (emulado):** FPR ✔ (XDP es 5,4–12,3 pts más bajo); ataques ✘: XDP pierde por
  **36,8–41,5 pts** (86–97 sesiones por semilla). → **FALLA por ataques.**
- Perfil `streamable` (cabeceras reales de 263 B): XDP 0 % / 0 % / 0 % en todas las semillas;
  nft también 0 %; string igual que en `minimo`. FALLA contra string; contra nft empata en 0 (falla por «estrictamente mayor»).

**Anomalías MCP (familia `grafo`, 100 %):** no cuentan para el umbral. Todas son detecciones *después*
de que el pedido llegó (bloqueo en `grafo` = 0 % en las 5 semillas), y con cabeceras reales caen a 0 %.
Es una capacidad que las líneas base no tienen, pero no es «ataque bloqueado» y no está demostrada en
condiciones realistas.

## 1. Commit, árbol y `src/`
- HEAD = `43ffd0b`, árbol limpio (solo ignorados: `target/`, `__pycache__/`, `resultados/crudo/`).
- `git diff 2713a16 43ffd0b -- src bpf build.rs Cargo.toml` vacío: **no toca `src/`** (ni el BPF).

## 2. Tests y clippy
- `cargo clippy --all-targets --release -- -D warnings`: limpio.
- `cargo test --release`: **19/19**.

## 3. Números vs resultados versionados
- `crudo/` coincide byte a byte con `crudo.tar.xz` (121 archivos).
- Todos los rangos de `VALOR.md` coinciden con `resumen.json` por semilla (tabla de arriba).
- Conteos de capas (suma 5 semillas, del log del cargador): detecciones grafo 211, literal 74,
  truncado 110 (= 395); FP truncado 106, literal 32. **Coinciden.**

## 4. Rerun
Clon aparte en `/tmp/aud4/clon` (no pisa archivos versionados), `bash scripts/experimento-valor.sh`
con las 5 semillas, ~3,6 min, `sudo -n` disponible. Limpieza verificada: `lo` sin XDP y sin tabla `fnbr_valor`.
- Corpus regenerados idénticos a los versionados (`cmp`, 5/5).
- TPR bloqueo, TPR detección y FPR de nft, string y XDP, en ambos perfiles: **idénticos por semilla**
  al original; conteos por capa también idénticos.
- Latencia (ruidosa, caja compartida): XDP p50 43–47 µs, p99 329–372 µs, 151 pedidos cortados
  (original: 171). No entra en el umbral. Resumen completo en `experimentos/valor/auditoria/rerun-resumen.md`.

## 5. Revisión de método
**Mismo corpus y mismos bytes:** sí. nft y XDP corren en red con `replay.py`; el string emulado aplica
`baseline.emulate` sobre `replay.http(...)`, la misma función determinista que genera los bytes que se
envían. Las tres usan el mismo `seed-N.jsonl`.

**Fidelidad de la emulación de `xt_string`:** subcadena ASCII sin mayúsculas sobre el payload HTTP completo.
- bm vs kmp: con un skb lineal ambos dan la misma respuesta (búsqueda exacta); la emulación es agnóstica al algoritmo.
- `--icase`: `bytes.lower()` solo toca ASCII, igual que el `toupper` del kernel. Equivalente.
- Offsets: `xt_string` sin `--from/--to` busca desde el byte 0 del paquete (incluye cabeceras IP/TCP)
  hasta 65535; la emulación no incluye cabeceras IP/TCP (binarias, sin efecto práctico con estas palabras).
- Segmentación: el pedido más grande del corpus tiene 1065 B; en `lo` (MTU 65536) va en un solo
  segmento. **No hay segmentación** en este experimento; en red real con pedidos > MSS, `xt_string`
  (por paquete) perdería palabras partidas entre segmentos y la emulación sobreestimaría.
- Ningún paso que no sea el objetivo (init, sonda) dispara la lista: los bloqueos del string son del pedido objetivo.
- Caveat: no es `xt_string` real (el kernel no lo tiene); sin latencia ni efectos TCP.

**nftables «real»:** es una línea base débil (comparación de prefijos en offsets fijos, ~240 B de payload,
variantes de mayúsculas). Aun así, el XDP falla contra ella por FPR.

**Todo lo que el XDP bloquea es literal de kernel:** en las 5 semillas, el 100 % de los ataques bloqueados
tiene como capa `kernel_literal` (0 por grafo, 0 por semántica, 0 por el bug).

## 6. Bug del byte 192
Causa: `CallGraph::observe` hace `extract_str_field(payload, "name").unwrap_or_default()`; si el valor de
`"name"` no termina dentro del prefijo de 192 B (o la clave no aparece), devuelve `""`, que no está en la
lista blanca → `ToolNotAllowed("")`. No es solo «truncado justo en 192»: alcanza con que el nombre no
quede completo en el prefijo.

Reproducción mínima (`experimentos/valor/auditoria/repro_byte192.rs`, crate aparte con dependencia por path):
```
prefijo 210 B (completo)                 -> None
prefijo 177 B (…"name":"weather")        -> None
prefijo 176 B (…"name":"weather)         -> Some(ToolNotAllowed(""))
prefijo 171 B (…"name":"we)              -> Some(ToolNotAllowed(""))
prefijo 169 B (…"name":")                -> Some(ToolNotAllowed(""))
prefijo 164 B (…"na)                     -> Some(ToolNotAllowed(""))
```

### Discrepancia 23,9–24,8 % vs 5,1–7,7 %
No es una contradicción, son **métricas distintas** con el mismo denominador:
- **5,1–7,7 %** = TPR de **bloqueo** (el pedido objetivo nunca llegó al sumidero), sobre los 234 ataques,
  cabeceras de 96 B.
- **31,6–37,2 %** = TPR de **detección** (bloqueado **o** flujo cortado después: la sonda `ping` quedó sin
  respuesta), mismo denominador y perfil.
- **23,9–24,8 %** = esa detección **descontando** las sesiones cuya única capa fue el truncado
  (56–58 de 234 por semilla). Es un descuento sobre los logs, **no** el bug arreglado y re-corrido.
  Baja desde 31,6–37,2 %, no desde 5,1–7,7 %. De ese ~24 %, ~18 pts son `grafo` (tardío) y ~6 pts literal de kernel.

### Sensibilidad sin el bug (análisis, no cambia el veredicto)
Como el bug nunca bloquea (actúa en espacio de usuario, después), arreglarlo **no cambia** el bloqueo:
sigue en 5,1–7,7 %. Cambia el FPR: quitando los FP cuya única capa es el truncado, queda
**1,4–4,5 %** (6, 10, 7, 3, 6 de 220).
- vs nft: ataques ✔; FPR XDP − nft = +1,8 / +3,6 / −0,5 / +0,9 / +0,5 pts → pasaría en 4 de 5 semillas y
  **fallaría en la semilla 2 por 1,6 pts**. Margen en ataques chico (+2 a +9 sesiones) y todo por
  literales de kernel, o sea otra lista estática con otra ventana, no la capa semántica.
- vs string emulado: **sigue perdiendo** por ~37–41 pts en bloqueo. Aun la detección con el bug descontado
  (23,9–24,8 %) o la detección cruda (31,6–37,2 %) quedan debajo de 41,9–47,4 % en cada semilla.
- Cota optimista con ventana arreglada: unión del bloqueo literal de kernel con el semántico sin ventana
  (offline, cuerpo completo) = 35,5–37,6 % de bloqueo (FPR 7,7–10,0 %), todavía **7–11 pts debajo** del string
  en cada semilla. Con estas reglas, ni arreglando bug y ventana vence al string emulado en ataques.

## Caveats
- String `--icase` emulado, no `xt_string` real (no está en el kernel); sin segmentación (1 pedido = 1 segmento en `lo`).
- Corpus sintético por plantillas; la lista de palabras la escribió quien conocía las familias (sesgo posible a favor del string).
- Solo `lo` con `xdpgeneric`, HTTP/1.1 en claro.
- La sensibilidad sin bug se calcula descontando sobre logs; no re-corrí con el bug arreglado (no se tocó `src/`).
- Latencia medida desde Python en caja compartida: solo órdenes de magnitud.
