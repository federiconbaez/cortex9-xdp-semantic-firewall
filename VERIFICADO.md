# VERIFICADO — criterio de aprobado del #4

Cuenta como **aprobado** solo si se cumplen todos:

1. `cargo build` compila el BPF (`clang -target bpf`) y el binario sin errores.
2. `cargo test` en verde (layout C↔Rust, patrones, clasificador, grafo).
3. `cargo clippy --all-targets -- -D warnings` sin warnings.
4. `bash scripts/demo.sh` con sudo imprime `RESULTADO: PASS`, que exige:
   - `benigno_mcp`: los 2 pedidos reciben eco (no hay falso positivo).
   - `inyeccion_literal_kernel`: el pedido **no** recibe eco (XDP_DROP en kernel).
   - `inyeccion_ofuscada_usuario`: el 2.º pedido **no** recibe eco (bloqueo desde usuario).
   - `grafo_call_antes_de_init`: el 2.º pedido **no** recibe eco (anomalía de grafo).
   - En estos dos casos el 1.º pedido no se exige: la decisión de usuario llega
     después de que el segmento entró. En 1 de 6 corridas el eco del 1.º también
     se cortó (carrera real, documentada en LIMITES.md).
   - Al terminar, `lo` queda **sin** XDP adjuntado.

**No** cuenta como verificado (y no se afirma): funcionamiento sobre TLS,
sobre stdio, a velocidad de línea en modo driver, ni detección general de
inyección de prompts.

## Estado al 20/10/2026 (America/Buenos_Aires)
Los 4 puntos: **cumplidos**; la demo pasó 6 veces seguidas tras el ajuste. Ver `evidencia/demo-2026-10-20.txt`.
