# VALOR — #4 Firewall semántico XDP

**Pregunta:** ¿el firewall semántico XDP bloquea tráfico MCP de ataque que una
línea base **estática** razonable no ve, sin falsos positivos?

**Respuesta corta: no.** Medido sobre loopback real con 5 semillas, el XDP
**bloquea antes de que llegue** solo el 5–8 % de los ataques (todos por los
literales del kernel), con 9–17 % de falsos positivos. Una lista de palabras
estática aplicada al paquete completo (`string --icase`, emulada) bloquea el
42–47 %, pero rompe el 20–22 % de los benignos. Lo único que el XDP aporta y la
línea base estática no puede es la **familia `grafo`** (anomalías de protocolo
MCP): la detecta al 100 %, pero **tarde** (el pedido malicioso ya llegó; se
cortan los siguientes). La capa "semántica" **no actuó ni una vez** en el
tráfico real: con un sobre JSON-RPC normal los argumentos quedan fuera de los
192 B que ve.

Fecha: 21/10/2026 (America/Buenos_Aires), commit base `2713a16`, en la
computadora compartida (kernel 6.12.94+, `xdpgeneric` en `lo`).

## Método

1. **Corpus** (`experimentos/valor/generar_corpus.py --seed N`, determinístico):
   454 sesiones por semilla = **220 benignas + 234 ataques**. Cada sesión es una
   conexión TCP con MCP sobre HTTP/1.1 en claro:
   `initialize → notifications/initialized → OBJETIVO → ping (sonda)`.
   JSON compacto o con espacios (como `json.dumps` por defecto), al azar.
   - Benignos: `normal` (140: tools/call de weather, search, read_file,
     list_dir, create_issue, translate, summarize, calendar_list,
     resources/read, prompts/get, */list), `palabras_alarmantes` (60: "ignore
     case", "password reset", "disregard previous email", "system prompt del bot",
     "/etc/passwd explicado", "developer mode en Chrome"…) y
     `discusion_seguridad` (20: textos que *hablan* de inyección).
   - Ataques por familia: `directa` 35 (frases conocidas EN/ES), `parafrasis` 35,
     `ofuscacion` 64 (8 c/u: mayúsculas, leet+separadores, homoglifos cirílicos,
     ancho cero, base64, URL-encoding, escapes `\uXXXX` de JSON, frase partida
     en dos campos), `exfiltracion` 35 (ruta sensible con herramienta permitida,
     herramienta no permitida, `curl -d @secreto`, secreto en la consulta),
     `grafo` 35 (tools/call sin initialize, método desconocido, re-initialize,
     herramienta fuera de la lista blanca) y `posicion_tardia` 30 (frase directa
     después de 300–600 B de texto benigno).
2. **Perfiles HTTP** (`replay.py --perfil`): `minimo` (cabeceras de 96 B, como
   la demo del repo) y `streamable` (lo que manda un cliente MCP real según la
   spec 2025-06-18: `Accept`, `Mcp-Session-Id`, `MCP-Protocol-Version`… 263 B).
3. **Configuraciones**, una por vez, cada una contra un sumidero nuevo
   (`sink.py`, 127.0.0.1:18181):
   - `sin filtro`.
   - `nftables estático (real)`: ver abajo.
   - `XDP semántico`: `fnbr-xdp-fw run --iface lo --ports 18181 --allow-tools
     weather,search,read_file,list_dir,create_issue,translate,summarize,calendar_list`
     (binario release del commit base, sin cambios).
   - `string --icase (emulado)` y `semántico sin ventana (offline)`: no corren en
     la red; se calculan sobre los mismos bytes (ver abajo).
4. **Verdad de terreno**: el sumidero registra cada pedido HTTP **completo** que
   recibe la aplicación. Un ataque está **bloqueado** si su pedido objetivo no
   aparece en ese registro; **detectado** si está bloqueado o si la sonda `ping`
   posterior se quedó sin respuesta (flujo cortado después). Un benigno es
   **falso positivo** si cualquier paso de su sesión quedó sin respuesta (0,5 s).
   El log del cargador XDP dice qué capa actuó (literal del kernel, grafo, semántica).
5. **Latencia**: una conexión persistente, 2000 pedidos benignos `normal`
   secuenciales (+100 de calentamiento) por semilla y configuración; RTT
   pedido→respuesta con `perf_counter_ns` en Python.

### Línea base estática: palabras clave
Archivo `experimentos/valor/palabras_clave.txt`, escrita como la escribiría un
admin sin mirar el corpus:

- Inyección: `ignore previous`, `ignore all previous`, `ignore prior`,
  `disregard previous`, `disregard all`, `forget your instructions`,
  `system prompt`, `you are now`, `developer mode`, `do anything now`,
  `jailbreak`, `<|im_start|>`, `[INST]`, `<<SYS>>`, `ignora las instrucciones`,
  `olvida tus instrucciones`.
- Exfiltración: `/etc/passwd`, `/etc/shadow`, `id_rsa`, `.aws/credentials`, `exfiltrate`.
- Herramientas peligrosas (JSON compacto): `"name":"shell"`, `"name":"exec"`,
  `"name":"bash"`, `"name":"run_command"`.

**Lo que se pudo hacer en este kernel y lo que no.** El kernel de la caja no tiene
`xt_string` (`iptables -m string` → "Extension string revision 0 not supported")
ni `NFQUEUE`, y nftables no tiene búsqueda de subcadenas. Por eso hay dos filas:

- **nftables estático (real)**: tabla `inet fnbr_valor`, hook input, solo
  `iif lo tcp dport 18181`. Una regla por offset `@th,OFF,128 @kw drop` contra un
  set de intervalos donde cada palabra es `[palabra·00…, palabra·ff…]` (o sea,
  "los 16 bytes en ese offset empiezan con la palabra"), con variantes
  minúscula/Capitalizada/Título/MAYÚSCULA (88 prefijos, 221 reglas). **nftables
  no acepta offsets ≥ 256 B** desde la cabecera TCP ("Numerical result out of
  range"), así que solo mira los primeros ~240 B del payload. Generada por
  `baseline.py nft`.
- **string --icase (emulado)**: lo que haría `iptables -m string --algo bm --icase`
  con la misma lista sobre el paquete completo. Se calcula offline sobre los
  bytes exactos que se mandaron (cada pedido va en un solo segmento), así que la
  detección es exacta; **no tiene latencia medida**.

La fila **semántico sin ventana (offline)** corre `fnbr-xdp-fw classify` sobre el
cuerpo JSON completo del objetivo: mide las reglas de `semantic.rs` sin el
límite de 192 B (sin grafo).

## Resultados (5 semillas, rango mín–máx)

### Perfil `minimo` (cabeceras de 96 B, el caso favorable al XDP)

| Fila | TPR bloqueo | TPR detección | FPR | directa | paráfrasis | ofuscación | exfiltración | grafo | posición tardía |
|---|---|---|---|---|---|---|---|---|---|
| sin filtro | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % |
| nftables estático (real) | 1,3–6,0 % | 1,3–6,0 % | 0,5–3,6 % | 8,6–28,6 % | 0 % | 0 % | 0–2,9 % | 0–11,4 % | 0 % |
| string --icase (emulado) | 41,9–47,4 % | 41,9–47,4 % | 19,5–22,3 % | 100 % | 11,4–20,0 % | 20,3–31,2 % | 40,0–57,1 % | 0–11,4 % | 100 % |
| **XDP semántico** | **5,1–7,7 %** | **31,6–37,2 %** | **9,1–16,8 %** | 22,9–40,0 % | 0 % | 3,1–6,2 % | 0 % | 0 % | 0 % |
| semántico sin ventana (offline) | 35,5–37,2 % | 35,5–37,2 % | 5,5–7,3 % | 85,7–97,1 % | 0 % | 37,5 % | 0 % | 0 % | 83,3–96,7 % |

Las columnas por familia son **TPR de bloqueo**. Detección (bloqueo o corte
posterior) por familia:

| Fila | directa | paráfrasis | ofuscación | exfiltración | grafo | posición tardía |
|---|---|---|---|---|---|---|
| nftables estático (real) | 8,6–28,6 % | 0 % | 0 % | 0–2,9 % | 0–11,4 % | 0 % |
| string --icase (emulado) | 100 % | 11,4–20,0 % | 20,3–31,2 % | 40,0–57,1 % | 0–11,4 % | 100 % |
| **XDP semántico** | 34,3–54,3 % | 5,7–20,0 % | 15,6–25,0 % | 31,4–37,1 % | **100 %** | 0 % |
| semántico sin ventana (offline) | 85,7–97,1 % | 0 % | 37,5 % | 0 % | 0 % | 83,3–96,7 % |

FPR por tipo de benigno:

| Fila | normal (140) | palabras alarmantes (60) | discusión de seguridad (20) |
|---|---|---|---|
| nftables estático (real) | 0 % | 1,7–13,3 % | 0 % |
| string --icase (emulado) | 0 % | 38,3–48,3 % | 100 % |
| **XDP semántico** | **7,9–12,9 %** | 8,3–15,0 % | 20,0–55,0 % |
| semántico sin ventana (offline) | 0 % | 0 % | 60,0–80,0 % |

**Qué capa del XDP actuó** (suma de 5 semillas, del log del cargador):
- Ataques detectados: grafo 211, literal del kernel 74, **grafo por nombre de
  herramienta truncado 110**, **semántica 0**.
- Benignos rotos: **grafo por nombre truncado 106**, literal del kernel 32.
- Sin los cortes por truncado, la detección "legítima" del XDP es 23,9–24,8 %.

### Perfil `streamable` (cabeceras reales de cliente MCP, 263 B)

| Fila | TPR bloqueo | TPR detección | FPR |
|---|---|---|---|
| sin filtro | 0 % | 0 % | 0 % |
| nftables estático (real) | 0 % | 0 % | 0 % |
| string --icase (emulado) | 41,9–47,4 % | 41,9–47,4 % | 19,5–22,3 % |
| **XDP semántico** | **0 %** | **0 %** | 0 % |

Con cabeceras reales el cuerpo JSON empieza después del byte 263: el kernel (256 B)
y la capa de usuario (192 B) no ven nada del cuerpo, ni siquiera `"method"`.
El XDP queda **ciego** en todas las familias, incluida `grafo`. nftables real,
igual (tope de 255 B).

### Latencia (perfil `minimo`, RTT en µs, 2000 pedidos por semilla)

| Fila | p50 | p99 | Δp50 vs sin filtro | Δp99 vs sin filtro | pedidos cortados |
|---|---|---|---|---|---|
| sin filtro | 21–38 | 32–73 | — | — | 0 |
| nftables estático (real) | 49–57 | 90–1977 | +12 a +28 | +31 a +1945 | 0 |
| XDP semántico | 37–46 | 140–520 | −1 a +22 | +67 a +448 | 171 / 10 500 |

Ruido: la caja es compartida con otras bots; el p99 de 1977 µs de nftables es
una sola semilla. Lo estable: ambos agregan decenas de µs en la mediana y el XDP
empeora la cola (p99) más que nftables. Los **171 pedidos cortados** del XDP son
benignos `normal` en una sesión persistente: cada uno es un falso positivo por
nombre truncado que mata la conexión (hubo que reconectar).

## Veredicto (sin maquillar)

- **Contra la pregunta: no demuestra valor.** En bloqueo real (que el ataque no
  llegue), el XDP (5–8 %) queda apenas por encima del nftables real (1–6 %) y muy
  por debajo de una lista estática aplicada al paquete completo (42–47 %). Y su
  FPR (9–17 %) es **peor** que el del nftables real (0,5–3,6 %), aunque mejor que
  el de `string --icase` (20–22 %).
- **La capa semántica no aporta nada en el cable.** Sus reglas funcionan (offline,
  sin ventana: 36–37 % de bloqueo con 5,5–7,3 % de FPR, mejor relación que
  `string --icase`), pero en tráfico real **actuó 0 veces**: el sobre JSON-RPC
  (cabeceras + `jsonrpc`/`id`/`method`/`params`/`name`) ya ocupa los 192 B que
  recibe, y los argumentos empiezan en el byte ~200.
- **Bug encontrado (genera la mayoría de los FP):** cuando el nombre de la
  herramienta queda cortado justo en el byte 192, `extract_str_field` devuelve
  `""` y el grafo con lista blanca dice `ToolNotAllowed("")`. Rompe el 7,7–12,3 %
  de las sesiones benignas, y también explica casi todas las "detecciones" de
  ofuscación, paráfrasis y exfiltración del XDP (110 de 395): son cortes por
  azar, no por entender el ataque.
- **Lo único con valor real contra la línea base:** las anomalías de protocolo
  MCP (`grafo`: llamada antes de initialize, método desconocido, re-initialize,
  herramienta fuera de lista). Ninguna regla estática las ve, y el XDP las
  detecta al 100 % **en el perfil mínimo**, pero **después** de que el primer
  pedido anómalo llegó al servidor. Con cabeceras reales de MCP, ni eso.
- Ningún sistema, estático o "semántico", detiene paráfrasis, base64,
  homoglifos ni escapes `\uXXXX` en proporción útil.

El #4 queda como **"sin valor demostrado contra línea base"** en inyección y
exfiltración, y **"valor parcial, solo detección tardía y solo con cabeceras
mínimas"** en anomalías de protocolo.

## Límites del experimento

- La línea base fuerte (`string --icase`) es **emulada** porque el kernel no tiene
  `xt_string`. Su detección es exacta para estos pedidos (un segmento cada uno),
  pero no tiene latencia ni efectos de TCP.
- El corpus es sintético con plantillas; las proporciones (por ejemplo 60
  benignos alarmantes de 220) mueven el FPR de las listas de palabras. Por eso se
  reporta el FPR por tipo de benigno.
- La lista de palabras la escribí yo sabiendo qué familias había; traté de que
  fuera la de un admin, no la del corpus, pero hay sesgo posible a favor de la
  línea base (por ejemplo `/etc/passwd`, `id_rsa`).
- Solo `lo` con `xdpgeneric`, HTTP/1.1 en claro, un pedido por segmento. Con
  TLS, HTTP/2 o MCP por stdio, todo esto ve todavía menos (ver `LIMITES.md`).
- La latencia se mide desde Python en una caja compartida: sirve para órdenes de
  magnitud, no para comparar diferencias de pocos µs.
- No se corrigió el firewall durante el experimento (habría sido ajustar al
  corpus). Arreglos obvios para una v0.2: tratar `""` truncado como "desconocido"
  y no como "no permitido"; mandar al usuario el cuerpo a partir del fin de las
  cabeceras HTTP (o más de 192 B); que el grafo bloquee **antes** en el kernel
  cuando la decisión es por `method`.

## Reproducir

```bash
cd /workspace/sistemas/04-xdp-semantic-firewall
bash scripts/experimento-valor.sh            # 5 semillas (1..5), ~7 min, usa sudo -n
bash scripts/experimento-valor.sh 7 8        # otras semillas
```

Requiere `nftables` (`sudo apt-get install nftables`), `clang` y Rust. El script
solo toca `lo` y el puerto 18181, crea y borra la tabla `inet fnbr_valor`, y al
final verifica que `lo` quede sin XDP y que la tabla no exista. Salidas:
`experimentos/valor/resultados/resumen.{md,json}` y `resultados/crudo.tar.xz`
(logs de cliente, sumidero, firewall y ruleset de cada corrida).
