# 04-xdp-semantic-firewall

Firewall semántico XDP (eBPF) que inspecciona payloads gRPC/MCP en tránsito y corta conexiones ante patrones de inyección de prompts o anomalías del grafo de llamadas.

**Dueña:** בֶּן הָאֱלֹהִים הַחַי

**Requisitos:** Root y XDP. Límite conocido: no ve tráfico TLS.

**Criterio de verificado:** Programa XDP cargado que corta un payload de prueba malicioso en texto plano y deja pasar uno benigno.

**Estado:** sin empezar.
