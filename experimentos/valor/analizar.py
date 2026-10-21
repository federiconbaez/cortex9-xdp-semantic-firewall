#!/usr/bin/env python3
"""Cruza replay (cliente) + log del sumidero (verdad de terreno) + log del
firewall, y produce las tablas del experimento de valor (rangos sobre semillas).

Definiciones (por sesión):
  ataque BLOQUEADO  = el pedido objetivo NUNCA llegó a la aplicación (no está en el log del sumidero).
  ataque DETECTADO  = bloqueado, o llegó pero el flujo quedó cortado después (la sonda ping no tuvo respuesta).
  benigno FP        = cualquier paso de la sesión sin respuesta (la sesión legítima se rompió).
Fila extra `string_icase_emulado`: lo que haría `iptables -m string --algo bm --icase`
con la misma lista de palabras sobre el paquete completo (offline, sin latencia).
"""
import argparse, collections, json, os, re, statistics, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baseline import emulate, keywords  # noqa: E402
from replay import http  # noqa: E402

CFGS = ["sin_filtro", "nft", "xdp"]
NOMBRE = {"sin_filtro": "sin filtro", "nft": "nftables estático (real)",
          "string_icase_emulado": "string --icase (emulado)", "xdp": "XDP semántico",
          "semantico_offline": "semántico sin ventana (offline)"}
FAMS = ["directa", "parafrasis", "ofuscacion", "exfiltracion", "grafo", "posicion_tardia"]
BSUB = ["normal", "palabras_alarmantes", "discusion_seguridad"]
FW_RE = re.compile(r"^\[(KERNEL DROP|USER BLOCK)\] 127\.0\.0\.1:(\d+) -> 127\.0\.0\.1:(\d+)(.*)$")


def load_jsonl(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def fw_reasons(path, port):
    out = collections.defaultdict(set)
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        m = FW_RE.match(line.strip())
        if not m:
            continue
        a, b = int(m.group(2)), int(m.group(3))
        client = a if b == port else b
        if m.group(1) == "KERNEL DROP":
            out[client].add("kernel_literal")
        elif 'ToolNotAllowed("")' in m.group(4):
            # el nombre de la herramienta quedó cortado en el prefijo de 192 B: artefacto, no detección
            out[client].add("usuario_grafo_nombre_truncado")
        elif "grafo" in m.group(4):
            out[client].add("usuario_grafo")
        else:
            out[client].add("usuario_semantico")
    return out


def eval_run(rep, sink, fw):
    got = {r["id"] for r in sink if r["id"]}
    rows = []
    for s in rep:
        tipos = [p["tipo"] for p in s["pasos"]]
        ti = tipos.index("objetivo")
        llego = f"{s['id']}-{ti}" in got
        sonda_ok = s["pasos"][-1]["respuesta"]
        rows.append({"etiqueta": s["etiqueta"], "familia": s["familia"], "sub": s["subfamilia"],
                     "bloqueado": not llego, "detectado": (not llego) or (not sonda_ok),
                     "roto": not all(p["respuesta"] for p in s["pasos"]),
                     "capas": sorted(fw.get(s["puerto_origen"], []))})
    return rows


def eval_emulated(corpus, kws, perfil, port):
    rows = []
    for s in corpus:
        hit_at = None
        for i, p in enumerate(s["pasos"]):
            if emulate(kws, http(p["cuerpo"], port, perfil, s["id"], p["tipo"] != "init")):
                hit_at = i
                break
        ti = [p["tipo"] for p in s["pasos"]].index("objetivo")
        blk = hit_at is not None and hit_at <= ti
        rows.append({"etiqueta": s["etiqueta"], "familia": s["familia"], "sub": s["subfamilia"],
                     "bloqueado": blk, "detectado": hit_at is not None, "roto": hit_at is not None, "capas": []})
    return rows


def eval_semantic_offline(corpus, binary):
    """Clasificador semántico del repo sobre el CUERPO COMPLETO del objetivo
    (sin ventana de 192 B, sin grafo). Mide la calidad de las reglas en sí."""
    rows = []
    for s in corpus:
        t = [p for p in s["pasos"] if p["tipo"] == "objetivo"][0]["cuerpo"]
        out = subprocess.run([binary, "classify", t], capture_output=True, text=True, check=True).stdout
        blk = "semantic         = Malicious" in out
        rows.append({"etiqueta": s["etiqueta"], "familia": s["familia"], "sub": s["subfamilia"],
                     "bloqueado": blk, "detectado": blk, "roto": blk, "capas": []})
    return rows


def metrics(rows):
    atk = [r for r in rows if r["etiqueta"] == "ataque"]
    ben = [r for r in rows if r["etiqueta"] == "benigno"]
    m = {"tpr_bloqueo": sum(r["bloqueado"] for r in atk) / len(atk),
         "tpr_deteccion": sum(r["detectado"] for r in atk) / len(atk),
         "fpr": sum(r["roto"] for r in ben) / len(ben),
         "n_atk": len(atk), "n_ben": len(ben)}
    for f in FAMS:
        fa = [r for r in atk if r["familia"] == f]
        m[f"bloq_{f}"] = sum(r["bloqueado"] for r in fa) / len(fa)
        m[f"det_{f}"] = sum(r["detectado"] for r in fa) / len(fa)
    for b in BSUB:
        bb = [r for r in ben if r["sub"] == b]
        m[f"fpr_{b}"] = sum(r["roto"] for r in bb) / len(bb)
    subs = collections.defaultdict(list)
    for r in atk:
        subs[f"{r['familia']}/{r['sub']}"].append(r)
    m["sub"] = {k: (sum(x["bloqueado"] for x in v) / len(v), sum(x["detectado"] for x in v) / len(v), len(v))
                for k, v in sorted(subs.items())}
    capas = collections.Counter()
    for r in atk:
        if r["detectado"]:
            capas["+".join(r["capas"]) or "(sin registro)"] += 1
    m["capas"] = dict(capas)
    capas_fp = collections.Counter()
    for r in ben:
        if r["roto"]:
            capas_fp["+".join(r["capas"]) or "(sin registro)"] += 1
    m["capas_fp"] = dict(capas_fp)
    return m


def pct(xs):
    lo, hi = min(xs), max(xs)
    if abs(hi - lo) < 1e-9:
        return f"{100 * lo:.1f} %"
    return f"{100 * lo:.1f}–{100 * hi:.1f} %"


def us(xs):
    lo, hi = min(xs), max(xs)
    return f"{lo:.0f}–{hi:.0f}"


def quant(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(q * len(v)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--seeds", nargs="+", type=int, required=True)
    ap.add_argument("--palabras", required=True)
    ap.add_argument("--port", type=int, default=18181)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bin", default="target/release/fnbr-xdp-fw")
    a = ap.parse_args()
    kws = keywords(a.palabras)
    corpus_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
    res = collections.defaultdict(lambda: collections.defaultdict(list))  # perfil -> cfg -> [metrics por semilla]
    lat = collections.defaultdict(lambda: collections.defaultdict(list))
    for s in a.seeds:
        corpus = load_jsonl(f"{corpus_dir}/seed-{s}.jsonl")
        for perfil in ["minimo", "streamable"]:
            for cfg in CFGS:
                tag = f"{a.dir}/s{s}-{perfil}-{cfg}"
                rows = eval_run(load_jsonl(tag + ".replay.jsonl"), load_jsonl(tag + ".sink.jsonl"),
                                fw_reasons(tag + ".fw.log", a.port))
                res[perfil][cfg].append(metrics(rows))
            res[perfil]["string_icase_emulado"].append(metrics(eval_emulated(corpus, kws, perfil, a.port)))
        sem = metrics(eval_semantic_offline(corpus, a.bin))
        for perfil in ["minimo", "streamable"]:
            res[perfil]["semantico_offline"].append(sem)
        for cfg in CFGS:
            d = json.load(open(f"{a.dir}/s{s}-lat-{cfg}.lat.json"))
            v = d["rtt_us"]
            lat[cfg]["p50"].append(quant(v, 0.50))
            lat[cfg]["p99"].append(quant(v, 0.99))
            lat[cfg]["media"].append(statistics.fmean(v))
            lat[cfg]["fallas"].append(d["fallas"])
    for cfg in CFGS:
        lat[cfg]["d_p50"] = [x - y for x, y in zip(lat[cfg]["p50"], lat["sin_filtro"]["p50"])]
        lat[cfg]["d_p99"] = [x - y for x, y in zip(lat[cfg]["p99"], lat["sin_filtro"]["p99"])]

    order = ["sin_filtro", "nft", "string_icase_emulado", "xdp", "semantico_offline"]
    md = [f"Semillas: {a.seeds}. Rangos = mín–máx entre semillas. "
          f"{res['minimo']['xdp'][0]['n_atk']} ataques y {res['minimo']['xdp'][0]['n_ben']} benignos por semilla.\n"]
    md.append("## Latencia (perfil mínimo, RTT pedido→respuesta, µs, %d pedidos por semilla)\n" % len(
        json.load(open(f"{a.dir}/s{a.seeds[0]}-lat-sin_filtro.lat.json"))["rtt_us"]))
    md.append("| Config | p50 | p99 | Δp50 vs sin filtro | Δp99 vs sin filtro | fallas |")
    md.append("|---|---|---|---|---|---|")
    for cfg in CFGS:
        L = lat[cfg]
        md.append(f"| {NOMBRE[cfg]} | {us(L['p50'])} | {us(L['p99'])} | {us(L['d_p50'])} | {us(L['d_p99'])} | {sum(L['fallas'])} |")
    for perfil in ["minimo", "streamable"]:
        R = res[perfil]
        md.append(f"\n## Perfil HTTP `{perfil}`\n")
        md.append("| Config | TPR bloqueo | TPR detección | FPR | " + " | ".join(FAMS) + " |")
        md.append("|---|---|---|---|" + "---|" * len(FAMS))
        for cfg in order:
            M = R[cfg]
            fam = " | ".join(pct([m[f"bloq_{f}"] for m in M]) for f in FAMS)
            md.append(f"| {NOMBRE[cfg]} | {pct([m['tpr_bloqueo'] for m in M])} | {pct([m['tpr_deteccion'] for m in M])} | "
                      f"{pct([m['fpr'] for m in M])} | {fam} |")
        md.append("\nDetección (bloqueo o corte posterior) por familia:\n")
        md.append("| Config | " + " | ".join(FAMS) + " |")
        md.append("|---|" + "---|" * len(FAMS))
        for cfg in order:
            M = R[cfg]
            md.append(f"| {NOMBRE[cfg]} | " + " | ".join(pct([m[f"det_{f}"] for m in M]) for f in FAMS) + " |")
        md.append("\nFPR por tipo de benigno:\n")
        md.append("| Config | " + " | ".join(BSUB) + " |")
        md.append("|---|" + "---|" * len(BSUB))
        for cfg in order:
            M = R[cfg]
            md.append(f"| {NOMBRE[cfg]} | " + " | ".join(pct([m[f"fpr_{b}"] for m in M]) for b in BSUB) + " |")
        md.append("\nPor subfamilia de ataque (bloqueo / detección, rango entre semillas):\n")
        subs = sorted({k for m in R["xdp"] for k in m["sub"]})
        md.append("| Subfamilia | n (rango) | " + " | ".join(NOMBRE[c] for c in order[1:]) + " |")
        md.append("|---|---|" + "---|" * (len(order) - 1))
        for k in subs:
            ns = [m["sub"].get(k, (0, 0, 0))[2] for m in R["xdp"]]
            cells = []
            for cfg in order[1:]:
                b = [m["sub"][k][0] for m in R[cfg] if k in m["sub"]]
                d = [m["sub"][k][1] for m in R[cfg] if k in m["sub"]]
                cells.append(f"{pct(b)} / {pct(d)}")
            md.append(f"| {k} | {min(ns)}–{max(ns)} | " + " | ".join(cells) + " |")
        cap, capfp = collections.Counter(), collections.Counter()
        for m in R["xdp"]:
            cap.update(m["capas"])
            capfp.update(m["capas_fp"])
        md.append(f"\nCapa del XDP que actuó (suma de {len(R['xdp'])} semillas) — ataques detectados: {dict(cap)}; "
                  f"benignos rotos (FP): {dict(capfp)}\n")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out + ".md", "w").write("\n".join(md) + "\n")
    json.dump({"res": res, "lat": lat}, open(a.out + ".json", "w"), indent=1, default=lambda o: dict(o))
    print("\n".join(md))


if __name__ == "__main__":
    main()
