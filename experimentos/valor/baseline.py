#!/usr/bin/env python3
"""Línea base estática.

`nft`   : genera un ruleset nftables REAL para `lo` y un solo puerto. Este kernel
          no trae xt_string (iptables -m string) ni NFQUEUE, y nftables no tiene
          búsqueda de subcadenas; lo que sí tiene es comparar bytes crudos en un
          offset fijo (@th,OFF,128). Se enumera una regla por offset contra un
          set de intervalos: cada palabra clave k (≤16 B) es el intervalo
          [k·00…, k·ff…], o sea "los 16 bytes en este offset EMPIEZAN con k".
          Sensible a mayúsculas: se cargan variantes minúscula/Capitalizada/
          Título/MAYÚSCULA. Límite: no ve una palabra a <16 B del final del paquete.
`emular`: lo que haría `iptables -m string --algo bm --icase` (si el módulo
          existiera): subcadena sin mayúsculas en todo el paquete.
"""
import sys

TABLE = "fnbr_valor"


def keywords(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if line and not line.startswith("#"):
            out.append(line)
    return out


def variants(k):
    vs = {k.lower(), k.upper(), k[:1].upper() + k[1:].lower(), k.title(), k}
    return sorted(v for v in vs)


def nft_ruleset(kws, port, max_off):
    pref = set()
    for k in kws:
        for v in variants(k):
            pref.add(v.encode()[:16])
    # quitar prefijos contenidos en otro más corto (los intervalos no pueden solaparse)
    pref = sorted(pref)
    keep = [p for p in pref if not any(q != p and p.startswith(q) for q in pref)]
    elems = []
    for p in keep:
        lo = p + b"\x00" * (16 - len(p))
        hi = p + b"\xff" * (16 - len(p))
        elems.append(f"0x{lo.hex()}-0x{hi.hex()}")
    lines = [f"table inet {TABLE} {{",
             "  set kw { typeof @th,0,128; flags interval; elements = { " + ", ".join(elems) + " } }",
             "  chain entrada { type filter hook input priority 0; policy accept;",
             f"    iif \"lo\" tcp dport {port} ip length > 60 jump escaneo",
             "  }",
             "  chain escaneo {"]
    for off in range(20, max_off):
        lines.append(f"    @th,{off * 8},128 @kw counter drop")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n", len(keep)


def emulate(kws, data: bytes):
    low = data.lower()
    return [k for k in kws if k.lower().encode() in low]


if __name__ == "__main__":
    if sys.argv[1] == "nft":
        kw, port, maxoff = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
        rs, n = nft_ruleset(keywords(kw), port, maxoff)
        sys.stdout.write(rs)
        print(f"# {n} prefijos, {maxoff - 20} reglas de offset", file=sys.stderr)
