#!/usr/bin/env python3
"""Reproduce el corpus por TCP en loopback contra sink.py.

modo detectar : cada sesión en su propia conexión (puerto origen único y fijo
                para poder cruzar con el log del sumidero y del firewall).
modo latencia : una conexión persistente, N pedidos benignos "normales"
                secuenciales; mide RTT pedido→respuesta (perf_counter_ns).
"""
import argparse, concurrent.futures as cf, hashlib, json, socket, struct, threading, time

T_RESP = 0.5      # s de espera por respuesta antes de declarar "sin respuesta"
T_REACCION = 0.15 # s entre el objetivo y la sonda (la capa de usuario reacciona tarde)


def http(body: str, port: int, perfil: str, sid: str, after_init: bool) -> bytes:
    b = body.encode()
    if perfil == "minimo":
        h = f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(b)}\r\n\r\n"
    else:  # streamable HTTP como lo manda un cliente MCP real (spec 2025-06-18)
        h = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: mcp-client/1.17 node\r\n"
             "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n")
        if after_init:
            u = hashlib.sha1(sid.encode()).hexdigest()
            h += f"Mcp-Session-Id: {u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}\r\nMCP-Protocol-Version: 2025-06-18\r\n"
        h += f"Content-Length: {len(b)}\r\n\r\n"
    return h.encode() + b


def read_response(c):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = c.recv(65536)
        if not d:
            raise OSError("eof")
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    n = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":")[1])
    while len(rest) < n:
        d = c.recv(65536)
        if not d:
            raise OSError("eof")
        rest += d


class Ports:
    def __init__(self, base):
        self.next, self.lock = base, threading.Lock()

    def connect(self, port):
        while True:
            with self.lock:
                p = self.next
                self.next += 1
            c = socket.socket()
            c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                c.bind(("127.0.0.1", p))
                c.settimeout(T_RESP)
                c.connect(("127.0.0.1", port))
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return c, p
            except OSError:
                c.close()


def run_session(sess, port, perfil, ports):
    c, lp = ports.connect(port)
    res = []
    dead = False
    for p in sess["pasos"]:
        if p["tipo"] == "sonda":
            time.sleep(T_REACCION)
        data = http(p["cuerpo"], port, perfil, sess["id"], p["tipo"] not in ("init",))
        t0 = time.perf_counter_ns()
        ok = False
        if not dead:
            try:
                c.sendall(data)
                read_response(c)
                ok = True
            except OSError:
                dead = True
        res.append({"tipo": p["tipo"], "respuesta": ok, "rtt_us": (time.perf_counter_ns() - t0) / 1000 if ok else None,
                    "bytes": len(data)})
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    return {"id": sess["id"], "etiqueta": sess["etiqueta"], "familia": sess["familia"],
            "subfamilia": sess["subfamilia"], "estilo": sess["estilo"], "puerto_origen": lp, "pasos": res}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--port", type=int, default=18181)
    ap.add_argument("--perfil", choices=["minimo", "streamable"], default="minimo")
    ap.add_argument("--modo", choices=["detectar", "latencia"], default="detectar")
    ap.add_argument("--base-puerto", type=int, required=True)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--hilos", type=int, default=24)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    corpus = [json.loads(l) for l in open(a.corpus, encoding="utf-8")]
    ports = Ports(a.base_puerto)
    if a.modo == "detectar":
        with cf.ThreadPoolExecutor(a.hilos) as ex:
            out = list(ex.map(lambda s: run_session(s, a.port, a.perfil, ports), corpus))
        with open(a.out, "w") as f:
            for r in out:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        return
    bodies = [s["pasos"][2]["cuerpo"] for s in corpus if s["subfamilia"] == "normal"]
    init = corpus[0]["pasos"][0]["cuerpo"]
    rtts, fallas = [], 0

    def fresh():
        c, _ = ports.connect(a.port)
        for b, ai in ((init, False), ('{"jsonrpc":"2.0","method":"notifications/initialized"}', True)):
            c.sendall(http(b, a.port, a.perfil, "lat", ai))
            read_response(c)
        return c
    c = fresh()
    for i in range(a.n + 100):
        data = http(bodies[i % len(bodies)], a.port, a.perfil, "lat", True)
        t0 = time.perf_counter_ns()
        try:
            c.sendall(data)
            read_response(c)
        except OSError:
            fallas += 1
            c.close()
            c = fresh()
            continue
        if i >= 100:  # calentamiento
            rtts.append((time.perf_counter_ns() - t0) / 1000)
    json.dump({"rtt_us": rtts, "fallas": fallas}, open(a.out, "w"))


if __name__ == "__main__":
    main()
