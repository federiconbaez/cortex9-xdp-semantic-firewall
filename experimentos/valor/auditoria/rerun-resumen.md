Semillas: [1, 2, 3, 4, 5]. Rangos = mín–máx entre semillas. 234 ataques y 220 benignos por semilla.

## Latencia (perfil mínimo, RTT pedido→respuesta, µs, 2000 pedidos por semilla)

| Config | p50 | p99 | Δp50 vs sin filtro | Δp99 vs sin filtro | fallas |
|---|---|---|---|---|---|
| sin filtro | 27–37 | 42–108 | 0–0 | 0–0 | 0 |
| nftables estático (real) | 46–61 | 65–171 | 18–31 | -6–97 | 0 |
| XDP semántico | 43–47 | 329–372 | 6–19 | 221–317 | 151 |

## Perfil HTTP `minimo`

| Config | TPR bloqueo | TPR detección | FPR | directa | parafrasis | ofuscacion | exfiltracion | grafo | posicion_tardia |
|---|---|---|---|---|---|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 1.3–6.0 % | 1.3–6.0 % | 0.5–3.6 % | 8.6–28.6 % | 0.0 % | 0.0 % | 0.0–2.9 % | 0.0–11.4 % | 0.0 % |
| string --icase (emulado) | 41.9–47.4 % | 41.9–47.4 % | 19.5–22.3 % | 100.0 % | 11.4–20.0 % | 20.3–31.2 % | 40.0–57.1 % | 0.0–11.4 % | 100.0 % |
| XDP semántico | 5.1–7.7 % | 31.6–37.2 % | 9.1–16.8 % | 22.9–40.0 % | 0.0 % | 3.1–6.2 % | 0.0 % | 0.0 % | 0.0 % |
| semántico sin ventana (offline) | 35.5–37.2 % | 35.5–37.2 % | 5.5–7.3 % | 85.7–97.1 % | 0.0 % | 37.5 % | 0.0 % | 0.0 % | 83.3–96.7 % |

Detección (bloqueo o corte posterior) por familia:

| Config | directa | parafrasis | ofuscacion | exfiltracion | grafo | posicion_tardia |
|---|---|---|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 8.6–28.6 % | 0.0 % | 0.0 % | 0.0–2.9 % | 0.0–11.4 % | 0.0 % |
| string --icase (emulado) | 100.0 % | 11.4–20.0 % | 20.3–31.2 % | 40.0–57.1 % | 0.0–11.4 % | 100.0 % |
| XDP semántico | 34.3–54.3 % | 5.7–20.0 % | 15.6–25.0 % | 31.4–37.1 % | 100.0 % | 0.0 % |
| semántico sin ventana (offline) | 85.7–97.1 % | 0.0 % | 37.5 % | 0.0 % | 0.0 % | 83.3–96.7 % |

FPR por tipo de benigno:

| Config | normal | palabras_alarmantes | discusion_seguridad |
|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 0.0 % | 1.7–13.3 % | 0.0 % |
| string --icase (emulado) | 0.0 % | 38.3–48.3 % | 100.0 % |
| XDP semántico | 7.9–12.9 % | 8.3–15.0 % | 20.0–55.0 % |
| semántico sin ventana (offline) | 0.0 % | 0.0 % | 60.0–80.0 % |

Por subfamilia de ataque (bloqueo / detección, rango entre semillas):

| Subfamilia | n (rango) | nftables estático (real) | string --icase (emulado) | XDP semántico | semántico sin ventana (offline) |
|---|---|---|---|---|---|
| directa/literal | 35–35 | 8.6–28.6 % / 8.6–28.6 % | 100.0 % / 100.0 % | 22.9–40.0 % / 34.3–54.3 % | 85.7–97.1 % / 85.7–97.1 % |
| exfiltracion/comando_en_argumento | 6–10 | 0.0 % / 0.0 % | 33.3–50.0 % / 33.3–50.0 % | 0.0 % / 33.3–62.5 % | 0.0 % / 0.0 % |
| exfiltracion/herr_no_permitida | 5–10 | 0.0 % / 0.0 % | 20.0–62.5 % / 20.0–62.5 % | 0.0 % / 100.0 % | 0.0 % / 0.0 % |
| exfiltracion/ruta_sensible_herr_permitida | 7–12 | 0.0–8.3 % / 0.0–8.3 % | 33.3–66.7 % / 33.3–66.7 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| exfiltracion/secreto_en_consulta | 7–13 | 0.0 % / 0.0 % | 28.6–63.6 % / 28.6–63.6 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| grafo/herr_no_permitida | 4–13 | 0.0–37.5 % / 0.0–37.5 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 100.0 % | 0.0 % / 0.0 % |
| grafo/llamada_antes_de_init | 3–13 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 100.0 % | 0.0 % / 0.0 % |
| grafo/metodo_desconocido | 5–9 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 100.0 % | 0.0 % / 0.0 % |
| grafo/re_initialize | 7–17 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 100.0 % | 0.0 % / 0.0 % |
| ofuscacion/ancho_cero | 8–8 | 0.0 % / 0.0 % | 0.0–25.0 % / 0.0–25.0 % | 0.0 % / 0.0–25.0 % | 100.0 % / 100.0 % |
| ofuscacion/base64 | 8–8 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0–25.0 % | 0.0 % / 0.0 % |
| ofuscacion/escape_unicode_json | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0–25.0 % | 0.0 % / 0.0 % |
| ofuscacion/homoglifos | 8–8 | 0.0 % / 0.0 % | 0.0–12.5 % / 0.0–12.5 % | 0.0 % / 0.0–25.0 % | 0.0 % / 0.0 % |
| ofuscacion/leet_separadores | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0–25.0 % | 100.0 % / 100.0 % |
| ofuscacion/mayusculas | 8–8 | 0.0 % / 0.0 % | 100.0 % / 100.0 % | 25.0–50.0 % / 37.5–62.5 % | 100.0 % / 100.0 % |
| ofuscacion/partido_campos | 8–8 | 0.0 % / 0.0 % | 25.0–50.0 % / 25.0–50.0 % | 0.0 % / 12.5–37.5 % | 0.0 % / 0.0 % |
| ofuscacion/url | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0–25.0 % | 0.0 % / 0.0 % |
| parafrasis/parafrasis | 35–35 | 0.0 % / 0.0 % | 11.4–20.0 % / 11.4–20.0 % | 0.0 % / 5.7–20.0 % | 0.0 % / 0.0 % |
| posicion_tardia/literal_tras_preambulo | 30–30 | 0.0 % / 0.0 % | 100.0 % / 100.0 % | 0.0 % / 0.0 % | 83.3–96.7 % / 83.3–96.7 % |

Capa del XDP que actuó (suma de 5 semillas) — ataques detectados: {'usuario_grafo_nombre_truncado': 110, 'kernel_literal': 74, 'usuario_grafo': 211}; benignos rotos (FP): {'usuario_grafo_nombre_truncado': 106, 'kernel_literal': 32}


## Perfil HTTP `streamable`

| Config | TPR bloqueo | TPR detección | FPR | directa | parafrasis | ofuscacion | exfiltracion | grafo | posicion_tardia |
|---|---|---|---|---|---|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| string --icase (emulado) | 41.9–47.4 % | 41.9–47.4 % | 19.5–22.3 % | 100.0 % | 11.4–20.0 % | 20.3–31.2 % | 40.0–57.1 % | 0.0–11.4 % | 100.0 % |
| XDP semántico | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| semántico sin ventana (offline) | 35.5–37.2 % | 35.5–37.2 % | 5.5–7.3 % | 85.7–97.1 % | 0.0 % | 37.5 % | 0.0 % | 0.0 % | 83.3–96.7 % |

Detección (bloqueo o corte posterior) por familia:

| Config | directa | parafrasis | ofuscacion | exfiltracion | grafo | posicion_tardia |
|---|---|---|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| string --icase (emulado) | 100.0 % | 11.4–20.0 % | 20.3–31.2 % | 40.0–57.1 % | 0.0–11.4 % | 100.0 % |
| XDP semántico | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| semántico sin ventana (offline) | 85.7–97.1 % | 0.0 % | 37.5 % | 0.0 % | 0.0 % | 83.3–96.7 % |

FPR por tipo de benigno:

| Config | normal | palabras_alarmantes | discusion_seguridad |
|---|---|---|---|
| sin filtro | 0.0 % | 0.0 % | 0.0 % |
| nftables estático (real) | 0.0 % | 0.0 % | 0.0 % |
| string --icase (emulado) | 0.0 % | 38.3–48.3 % | 100.0 % |
| XDP semántico | 0.0 % | 0.0 % | 0.0 % |
| semántico sin ventana (offline) | 0.0 % | 0.0 % | 60.0–80.0 % |

Por subfamilia de ataque (bloqueo / detección, rango entre semillas):

| Subfamilia | n (rango) | nftables estático (real) | string --icase (emulado) | XDP semántico | semántico sin ventana (offline) |
|---|---|---|---|---|---|
| directa/literal | 35–35 | 0.0 % / 0.0 % | 100.0 % / 100.0 % | 0.0 % / 0.0 % | 85.7–97.1 % / 85.7–97.1 % |
| exfiltracion/comando_en_argumento | 6–10 | 0.0 % / 0.0 % | 33.3–50.0 % / 33.3–50.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| exfiltracion/herr_no_permitida | 5–10 | 0.0 % / 0.0 % | 20.0–62.5 % / 20.0–62.5 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| exfiltracion/ruta_sensible_herr_permitida | 7–12 | 0.0 % / 0.0 % | 33.3–66.7 % / 33.3–66.7 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| exfiltracion/secreto_en_consulta | 7–13 | 0.0 % / 0.0 % | 28.6–63.6 % / 28.6–63.6 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| grafo/herr_no_permitida | 4–13 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| grafo/llamada_antes_de_init | 3–13 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| grafo/metodo_desconocido | 5–9 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| grafo/re_initialize | 7–17 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| ofuscacion/ancho_cero | 8–8 | 0.0 % / 0.0 % | 0.0–25.0 % / 0.0–25.0 % | 0.0 % / 0.0 % | 100.0 % / 100.0 % |
| ofuscacion/base64 | 8–8 | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| ofuscacion/escape_unicode_json | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| ofuscacion/homoglifos | 8–8 | 0.0 % / 0.0 % | 0.0–12.5 % / 0.0–12.5 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| ofuscacion/leet_separadores | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0 % | 100.0 % / 100.0 % |
| ofuscacion/mayusculas | 8–8 | 0.0 % / 0.0 % | 100.0 % / 100.0 % | 0.0 % / 0.0 % | 100.0 % / 100.0 % |
| ofuscacion/partido_campos | 8–8 | 0.0 % / 0.0 % | 25.0–50.0 % / 25.0–50.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| ofuscacion/url | 8–8 | 0.0 % / 0.0 % | 0.0–37.5 % / 0.0–37.5 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| parafrasis/parafrasis | 35–35 | 0.0 % / 0.0 % | 11.4–20.0 % / 11.4–20.0 % | 0.0 % / 0.0 % | 0.0 % / 0.0 % |
| posicion_tardia/literal_tras_preambulo | 30–30 | 0.0 % / 0.0 % | 100.0 % / 100.0 % | 0.0 % / 0.0 % | 83.3–96.7 % / 83.3–96.7 % |

Capa del XDP que actuó (suma de 5 semillas) — ataques detectados: {}; benignos rotos (FP): {}

