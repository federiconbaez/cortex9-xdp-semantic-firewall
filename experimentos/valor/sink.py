#!/usr/bin/env python3
"""Sumidero MCP-sobre-HTTP mínimo en 127.0.0.1:PUERTO.
Parsea pedidos HTTP/1.1 (Content-Length), registra en LOG una línea JSON por
pedido COMPLETO recibido por la aplicación: {"puerto": peer, "n": k, "id": ...}.
Responde 200 con un JSON-RPC corto (o 202 a notificaciones).
Es la verdad de terreno: un pedido "llegó" solo si aparece en este log."""
import json, re, socket, sys, threading

PORT, LOG = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
logf = open(LOG, "a", buffering=1)
ID_RE = re.compile(rb'"id"\s*:\s*"([^"]+)"')


def handle(c, peer):
    c.settimeout(30)
    buf, n = b"", 0
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            m = re.search(rb"(?i)content-length:\s*(\d+)", head)
            need = int(m.group(1)) if m else 0
            while len(rest) < need:
                d = c.recv(65536)
                if not d:
                    return
                rest += d
            body, buf = rest[:need], rest[need:]
            mid = ID_RE.search(body)
            rid = mid.group(1).decode() if mid else None
            with lock:
                logf.write(json.dumps({"puerto": peer, "n": n, "id": rid}) + "\n")
            n += 1
            if rid is None:
                c.sendall(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
            else:
                out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(out) + out)
    except OSError:
        pass
    finally:
        c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(512)
print("sink listo", flush=True)
while True:
    c, addr = s.accept()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=handle, args=(c, addr[1]), daemon=True).start()
