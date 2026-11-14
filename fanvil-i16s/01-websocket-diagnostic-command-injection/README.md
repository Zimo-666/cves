# [CVE-TBD] Fanvil i16S V0.2.2-2.12.19 Unauthenticated OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: Fanvil
- Product: i16S
- Version or Commit: V0.2.2-2.12.19
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: https://github.com/Zimo-666/cves/tree/main/fanvil-i16s/01-websocket-diagnostic-command-injection
- Description:

```
An OS command injection vulnerability was discovered in Fanvil i16S firmware V0.2.2-2.12.19. The "Rapid Logic/1.1" HTTP server embedded in /customer/bin/I10V exposes the WebSocket diagnostic endpoints /Ping and /Traceroute without any authentication: a GET request that carries the WebSocket upgrade headers and no cookie is answered with HTTP/1.1 101 Switching Protocols. The first text frame is used as the diagnostic target address and is validated by uStrIsValidIPOrDomain() (libplatform_utils.so: uParaUrlParse() plus POSIX regular expressions), which accepts a newline (0x0A) because the value is only checked as a bare URL authority and not as a shell token. The unchecked value is then formatted with snprintf(buf, 0x40, "traceroute %s ") in netTracerouteTask() (and with snprintf(buf, 0x40, "ping %s -c 10 -W 1") in netPingTask()) and passed to popen(), i.e. to /bin/sh -c. The newline therefore terminates the intended traceroute command and everything after it is executed by the shell. I10V is started as root from /customer/demo.sh during boot, so the injected commands run with root privileges and no credentials are required. Reproduction: open an unauthenticated WebSocket to ws://<device>/Traceroute and send the text frame "127.0.0.1\nid"; the server streams back the traceroute output followed by "uid=0(root) gid=0(root) groups=0(root)". Any host that can reach the device web interface obtains root command execution with a single unauthenticated request; no user interaction or configuration is required. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: Unauthenticated command injection in the Fanvil i16S diagnostic WebSocket endpoints (/Ping and /Traceroute)

## Summary

The Fanvil i16S firmware V0.2.2-2.12.19 runs an embedded "Rapid Logic/1.1" HTTP server inside
`/customer/bin/I10V`. The server registers WebSocket endpoints `/echo`, `/log`, `/Ping` and
`/Traceroute`. None of them is covered by the cookie/Basic authentication that protects the
`/cgi-bin/*` and `/api/*` handlers: a WebSocket upgrade request without any cookie is
answered with `HTTP/1.1 101 Switching Protocols`.

The first text frame sent on `/Ping` or `/Traceroute` is treated as the diagnostic target.
It is validated by `uStrIsValidIPOrDomain()`, implemented in `libplatform_utils.so` with
`uParaUrlParse()` and a table of POSIX regular expressions (`uParaUrlCheck()`). That check
validates the value as a bare URL authority (no scheme, path, query or fragment) but does not
reject the newline byte. The value is subsequently copied into a stack buffer with
`snprintf(buf, 0x40, "traceroute %s ")` (or `snprintf(buf, 0x40, "ping %s -c 10 -W 1")`) and
executed with `popen()`, which runs the string through `/bin/sh -c`. A newline in the frame
therefore ends the intended command and starts an attacker-controlled second command.

## Affected Product and Firmware

- Vendor: Fanvil (Shenzhen Fanvil Technology Co., Ltd.)
- Product: i16S SIP video intercom / door phone
- Firmware: **V0.2.2-2.12.19**, build 2023-03-06 17:57:34, vdsp 0.29.0, vsot 0.2.2
- File: `I16S-fanvil-3925-full-V0.2.2-2.12.19-1710-D0.29.0-T2023-03-06-17.58.02.z`
  SHA-256 `ffd850be1697cc6ba948bc598526f684b03b03a746b46cb6824e4e0309bf977e`
- Latest firmware also verified vulnerable: **V0.2.2-2.12.52.15**, build 2026-02-05 11:07:36
  (`I16S-fanvil-3925-full-V0.2.2-2.12.52.15-2457-D0.29.0-T2026-02-05-11.07.36.z`,
  SHA-256 `fa1378f99afadb42e37e3577846a19622cb428d16e4dc6fb2e9d638be96cf9ac`); the same
  unauthenticated frame `127.0.0.1\nid` returned `uid=0(root)` on that build as well
- SoC: SigmaStar SSC325 (ARMv7, uClibc), Linux 4.9.84
- Vulnerable component: `/customer/bin/I10V` (ELF32 ARM EABI5, stripped, 4,417,104 bytes,
  SHA-256 `4ed209a26591bda2688335d41cecdc50c547f2ec721f89f958363d47ce51c34b`);
  the address validator is in `/lib/libplatform_utils.so.0.0.0`
- Web interface: TCP/80 (HTTP). The same server serves HTTPS when a certificate is configured.

## Vulnerability Details and Root Cause

### 1. Unauthenticated WebSocket endpoints

The WebSocket route table of I10V (`0x42F4B4`, 12-byte entries `{path,
message_callback, close_callback}`) contains `/echo`, `/log`, `/Ping` and `/Traceroute`; none
of the entries carries an authentication callback:

```
0042f4b4  "/echo"        0x00081441   0x00000000
0042f4c0  "/log"         0x00081455   0x00081365
0042f4cc  "/Ping"        0x00081585   0x00081351   (Thumb pointers, bit 0 set)
0042f4d8  "/Traceroute"  0x00081659   0x0008133d
``` A request such as:

```
GET /Traceroute HTTP/1.1
Host: <device>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
Sec-WebSocket-Version: 13
```

is answered with `101 Switching Protocols` although no `Cookie: auth=...` and no
`Authorization` header are supplied. The same request to `/cgi-bin/syslog?type=syslog`
without a session is answered with `401 Not Authorized`, which shows that the WebSocket
paths bypass the HTTP authentication layer.

### 2. Address validation accepts a newline

The `/Ping` message callback is `sub_81584` and the `/Traceroute` message callback is
`sub_81658`. Both call `uStrIsValidIPOrDomain()` before starting the diagnostic task:

```
if ( uStrIsValidIPOrDomain(target) ) { startDiagnostics(target, ...); }
else { send("WEB_APP_INVALID_ADDRESS_MSG"); }
```

`uStrIsValidIPOrDomain()` (0x564C in `libplatform_utils.so.0.0.0`) calls
`uParaUrlParse()` (0x69CC) and then requires that the parsed URL has no scheme, no path, no
user information, no query and no fragment. `uParaUrlParse()` calls `uParaUrlCheck()`
(0x67A4), which matches the string against seven POSIX extended regular expressions for
IPv4, IPv6, FQDN, host:port and `file://`/`http://` style authorities. The regular
expressions constrain the characters of the host part but the newline is not part of any
character class that is rejected and `$` anchoring is not used for every alternative, so
`"127.0.0.1\nid"` passes the check and is accepted as a valid target. The strings
`"127.0.0.1;id"`, `"127.0.0.1|id"` and `"127.0.0.1$(id)"` are rejected with
`WEB_APP_INVALID_ADDRESS_MSG`, confirming that the flaw is the missing rejection of the
newline in the URL-authority validation, not a general absence of validation.

### 3. Shell command construction

The validated target is handed to the diagnostic thread:

- `/Traceroute` -> `appWebTracerouteStartFunc` (`sub_3527C`) -> `netTracerouteTask`
  (`sub_35450`):
  `snprintf(s, 0x40, "traceroute %s ", target); popen(s, "r");`
- `/Ping` -> `appWebPingStartFunc` (`sub_35370`) -> `netPingTask` (`sub_3557C`):
  `snprintf(s, 0x40, "ping %s -c 10 -W 1", target); popen(s, "r");`

`popen()` executes the string with `/bin/sh -c`; the newline is a command separator, so the
text after it is executed as a second command. The 64-byte command buffer limits the total
length of the injected command line but not its content.

## Vulnerable Component / Function / Call Chain

```
WebSocket text frame (no authentication)
  -> /Traceroute connection callback                        sub_81658
  -> uStrIsValidIPOrDomain()                                libplatform_utils.so +0x564C
       -> uParaUrlParse()                                   +0x69CC
       -> uParaUrlCheck() (POSIX regexps)                   +0x67A4
  -> appWebTracerouteStartFunc                              sub_3527C
  -> netTracerouteTask                                      sub_35450
       snprintf(s, 0x40, "traceroute %s ", target)
       popen(s, "r")                                        /bin/sh -c
  -> command execution as root
```

`/Ping` uses the same flow through `sub_81584` -> `sub_35370` -> `sub_3557C`.

## Authentication Requirements and Attack Conditions

- Authentication: none. The WebSocket upgrade succeeds without a cookie or an
  `Authorization` header; only `/cgi-bin/*` and `/api/*` are protected by the session cookie.
- Network position: any host that can reach TCP/80 of the device (LAN, or the Internet if
  the web interface is exposed or NAT-forwarded).
- User interaction: none.
- Configuration: none; the diagnostic endpoints are registered unconditionally at startup.

## Proof of Concept and Reproduction

`poc.py` in this directory performs the unauthenticated WebSocket handshake, sends one text
frame and prints everything the device returns:

```
python3 poc.py --host <host> --path /Traceroute --cmd "id"
python3 poc.py --host <host> --path /Ping --cmd "id"
```

Expected output (observed on the tested firmware):

```
[+] WebSocket upgraded on <host>:80/Traceroute (no authentication)
[+] Sent frame: '127.0.0.1\nid'
[+] traceroute to 127.0.0.1 (127.0.0.1), 30 hops max, 38 byte packets
[+] 1  127.0.0.1 (127.0.0.1)  0.785 ms  0.015 ms  0.012 ms
[+] uid=0(root) gid=0(root) groups=0(root)
```

## Observed Results and Evidence

The firmware was executed in an isolated QEMU ARM user-mode chroot built from the tested
firmware partitions (`/`, `/config`, `/customer` extracted from the vendor image), in a
dedicated network namespace. The HTTP server returned `Server: Rapid Logic/1.1` and the
WebSocket handshake without credentials returned `HTTP/1.1 101 Switching Protocols`:

```
/Traceroute payload '127.0.0.1\nid'
   HTTP/1.1 101 Switching Protocols
   frame: traceroute to 127.0.0.1 (127.0.0.1), 30 hops max, 38 byte packets
   frame: 1  127.0.0.1 (127.0.0.1)  0.785 ms  0.015 ms  0.012 ms
   frame: uid=0(root) gid=0(root) groups=0(root)
   frame: WEB_APP_DIAGNOSTICS_CLOSE_MSG
```

The same test was repeated against the latest vendor firmware, V0.2.2-2.12.52.15
(2026-02-05, SHA-256 `fa1378f99afadb42e37e3577846a19622cb428d16e4dc6fb2e9d638be96cf9ac`):
the WebSocket upgrade still needs no authentication and the frame `127.0.0.1\nid` still
returned `uid=0(root) gid=0(root) groups=0(root)`. The process that owns the HTTP
server was started by `/customer/demo.sh` from the boot sequence without dropping
privileges, which is why the injected command reports `uid=0`.

The `/Ping` endpoint uses the same validator and the same `popen()` construction
(`"ping %s -c 10 -W 1"`); because the injected newline removes the `-c 10 -W 1` options from
the `ping` command, an injected `ping` keeps running and the diagnostic task stays busy, but
the injected command is executed in the same way.

## Security Impact

An unauthenticated attacker with access to the device web interface can execute arbitrary
shell commands as root. This allows reading the stored configuration (including SIP and web
credentials), modifying device settings, opening network services, and using the intercom as
a foothold in the video-surveillance / access-control network segment.

## CWE and CVSS Vector

- CWE-78: Improper Neutralization of Special Elements used in an OS Command
  ('OS Command Injection')
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8)

The vector is rated for an adjacent-network attacker because the diagnostic endpoints are
reachable on the device LAN; if the web interface is exposed to the Internet the attack
vector becomes `AV:N` (9.8).

## Related CVEs / Novelty Analysis

- No CVE for Fanvil i16S was found in the NVD (keyword `i16S`: 0 results, 2026-11-13).
- Related, but different products: CVE-2025-70518 / CVE-2025-70521 (Fanvil x7a 2.6.0.1182,
  diagnostic ping tool does not handle user input securely) and CVE-2025-64052 (Fanvil
  x210 V2 2.12.20, unauthenticated command execution). Both describe other models; the i16S
  shares the Rapid Logic diagnostic WebSocket code but is a distinct product and firmware
  family. The i16S-specific chain documented here (newline accepted by the URL-authority
  validator, command built by `netTracerouteTask`/`netPingTask` and executed by `popen`) is
  not covered by those advisories.

## Suggested Remediation

- Require the normal web session (or a dedicated authenticated channel) for `/Ping`,
  `/Traceroute`, `/echo` and `/log`.
- Replace the URL-authority validation with a strict allow-list check: parse the value as an
  IPv4/IPv6 address or as a hostname matching `[A-Za-z0-9.-]+` and reject any byte outside
  that set, including CR, LF, NUL and shell metacharacters.
- Do not build shell command lines from network input; use `execve()` with an argument
  vector (`/bin/ping`, `-c`, `10`, `-W`, `1`, target) and, where a host name is allowed,
  resolve it first and pass the numeric address.
- Drop privileges for the HTTP/diagnostic tasks.

## Disclosure Status

- Vendor notification: not yet performed.
- CVE: not assigned; `CVE-TBD`.
- The material is stored in a private repository; no public disclosure has been made.
