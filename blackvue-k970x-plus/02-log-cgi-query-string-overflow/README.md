# [CVE-TBD] BlackVue K970X Plus 1.003 Stack-based Buffer Overflow (CWE-121)

## VulDB Submission Fields

- Vendor: BlackVue (Pittasoft)
- Product: K970X Plus
- Version or Commit: 1.003 (English build, 2026-01-26)
- Vulnerability: Stack-based Buffer Overflow (CWE-121)
- Advisory / Exploit URL: https://github.com/Zimo-666/cves/tree/main/blackvue-k970x-plus/02-log-cgi-query-string-overflow
- Description:

```
A stack-based buffer overflow vulnerability was discovered in BlackVue K970X Plus firmware v1.003 (English build). The built-in Boa web server (Server: K970X_Plus) exposes /blackvue_log.cgi without authentication (generated /tmp/boa.conf contains "AuthType None"). The CGI reads the QUERY_STRING environment variable, locates the "path=d:" token with strstr(), and uses sprintf() to build "/app/sd/BlackVue%s" in a 128-byte stack buffer; the value is also copied with strcpy() into a 50-byte stack buffer. The saved return address lies at offset 148 from the start of the 128-byte destination buffer (20 bytes beyond it); the fixed prefix is 16 bytes, so a 132-byte path value overwrites it. Reproduction: curl -i "http://<dashcam-ip>/blackvue_log.cgi?path=d:$(python3 -c 'print("A"*132+"BBBB")')" returns HTTP 502 Bad Gateway because the CGI dies with SIGSEGV while Boa stays alive; using 0x42424242 as the last four bytes sets the program counter to 0x42424242, as verified with qemu-arm and gdb. The CGI runs as root, so the saved-return-address control is a code-execution primitive; a complete RCE chain was not demonstrated. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

### Summary

The BlackVue K970X Plus runs a customized Boa web server on TCP port 80 with
`AuthType None`. The CGI program `blackvue_log.cgi` trusts the `QUERY_STRING`
environment variable and copies the `path=d:` value into a fixed-size stack
buffer without a bounds check. The saved return address can be overwritten by a
single unauthenticated HTTP request; the CGI crashes (HTTP 502) and the saved
program counter is fully attacker-controlled.

### Affected Product and Firmware

- Vendor: BlackVue / Pittasoft (Korea)
- Product: K970X Plus (2-channel cloud dashcam, MStar ARM32 platform)
- Firmware: v1.003, English build, build date 2026-01-26 (vendor page lists
  Version 1.003, 2026-01-28, as the current release)
- Firmware archive SHA-256: `9de2efb60206d49e683f29882033e5cc98faf824ec442e8bc8288478827911aa`
- Web root: `/res/System/www` (squashfs rootfs, populated with the `data` partition)
- Web server: BlackVue-customized Boa, banner `K970X_Plus`, TCP port 80
- Generated `/tmp/boa.conf` contains: `Port 80`, `User root`, `Group root`,
  `DocumentRoot /res/System/www`, `CGIPath /res/System/www`, `AuthType None`
- Default credentials: none (`AuthType None`; default `ap_pw=` is empty)
- Component: `/res/System/www/blackvue_log.cgi` (12,240 bytes, ARM32 EABI5,
  dynamically linked, non-PIE, built without stack canary)
- Component SHA-256: `e8ecf28282205374cfbf7d36944564e8f01c0aa1df0d5459e0f1a38b1ffd650b`
- Firmware archive SHA-256: `9de2efb60206d49e683f29882033e5cc98faf824ec442e8bc8288478827911aa`
- Vendor firmware page:
  `https://media.blackvue.com/download/k970x-plus-firmware-english/`

### Vulnerability Details and Root Cause

`main` starts at `0x10524`, allocates a `0xc4` stack frame and saves
`lr` at `sp+0xd4`. It reads the attacker-controlled query string and performs:

```c
  qs = getenv("QUERY_STRING");                                   /* controlled */
  p  = strstr(qs, "path=d:");
  sprintf(sp + 0x40, "/app/sd/BlackVue%s", p + 7);               /* 128-byte buffer */
  strcpy (sp + 0x0c, p + 7);                                     /* 50-byte buffer  */
```

The destination is a 128-byte stack buffer at sp+0x40; the copy is unbounded. The distance from the
start of the destination to the saved `lr` is 148 bytes (20 bytes beyond the buffer); because the
format prefix is 16 bytes, a 132-byte query value reaches the saved `lr`. A value of that
length overwrites the saved return address with attacker bytes. The binaries are
built as non-PIE ET_EXEC without `__stack_chk_fail`, so no canary intervenes.

Call chain: `main -> getenv("QUERY_STRING") -> strstr("path=d:") -> sprintf(sp+0x40, "/app/sd/BlackVue%s", value) -> function return`.

The Boa request-line limit is 1024 bytes (larger URIs receive HTTP 414), which is
far above the 132-byte value required, so the overflow is reachable over
HTTP. The per-header-line limit (1024 bytes) is unrelated to the query string.

### Vulnerable Component / Function / Call Chain

- Component: `/res/System/www/blackvue_log.cgi`
- Function: `main` at `0x10524` (Thumb)
- Sink: `strcpy`/`sprintf` into `128-byte stack buffer at sp+0x40`
- Call chain: `main -> getenv("QUERY_STRING") -> strstr("path=d:") -> sprintf(sp+0x40, "/app/sd/BlackVue%s", value) -> function return`

### Authentication Requirements and Attack Conditions

- Authentication: none. The firmware-generated `/tmp/boa.conf` contains
  `AuthType None`; no credentials, cookies or tokens are checked.
- Network position: the dashcam Wi-Fi AP (`10.99.77.1`) or the same LAN when the
  device is associated as a station; TCP port 80.
- Input: one HTTP GET with a long query value. No file on the SD card is
  required.
- User interaction: none.

### Proof of Concept and Reproduction

The raw request is `poc-request.txt` (one GET request; `132` filler bytes
plus a four-byte marker at the saved return address).

Equivalent shell reproduction:

```bash
curl -i "http://<dashcam-ip>/blackvue_log.cgi?path=d:$(python3 -c 'print("A"*132+"BBBB")')"
```

Expected result: HTTP `502 Bad Gateway` (the CGI produced no valid CGI output
because it died), while `GET /index.html` still returns `200 OK` and the Boa
server remains alive. Under `qemu-arm` with `gdb` the faulting instruction
pointer is exactly `0x42424242`, proving control of the saved return address.

### Observed Results and Evidence

In an isolated ARM rehost using the firmware's own `boa`, the firmware glibc and
the genuine CGI binaries, with the production `/tmp/boa.conf` template (only the
listen port changed from 80 to 8080):

- A benign request with a short value -> `200 OK`; server alive.
- A benign request with a short value -> `200 OK`; server alive.
- `GET /blackvue_log.cgi?path=d:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...` (the full `poc-request.txt` value) -> `502 Bad Gateway`;
  the Boa CGI log records `qemu: uncaught target signal 11 (Segmentation fault)`;
  the server still answers `GET /index.html` with `200 OK`.
- `gdb` attached to `qemu-arm-static` reports `SIGSEGV` at `pc = 0x42424242`
  after the four-byte marker is placed at offset 132.

### Security Impact

An unauthenticated attacker on the dashcam Wi-Fi/LAN can corrupt the stack of a
root-owned CGI process and control its saved return address. This is a
code-execution primitive: a ROP chain can be placed in the same query value.
The demonstrated outcome is a crash of the CGI process (HTTP 502) and
control-flow hijack; a complete, ASLR-bypassing RCE chain was not demonstrated
in this report. Because the CGI runs as `root` (`User root` in `boa.conf`),
successful exploitation would give root-level code execution on the dashcam.

### CWE and CVSS Vector

- CWE-121: Stack-based Buffer Overflow
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8)

### Related CVEs / Novelty Analysis

- NVD keyword search for "BlackVue" returns 7 CVEs. None describes a stack
  overflow in `blackvue_log.cgi` or in any `/res/System/www` CGI:
  CVE-2023-27746 (weak WPA2 passphrase), CVE-2023-27747 (no web authentication),
  CVE-2023-27748 (no firmware authenticity check), CVE-2025-2355,
  CVE-2025-2356, CVE-2025-7075 (unauthenticated `/upload.cgi`),
  CVE-2025-7076 (unauthenticated configuration change via `/upload.cgi`).
- The team library contains a BlackVue DR750X-2CH entry for a heap overflow in
  Boa `CheckInnerFile` (`.thm`/`.gps`/`.3gf`/`S.mp4` suffix handler). That is a
  different component and a different root cause (heap `strcpy` in `boa` versus
  a stack copy in a CGI), and it is not duplicated here. The K970X `boa` has its
  own related `CheckInnerFile` stack overflow; it is intentionally not submitted
  as a separate CVE to avoid duplicating that root cause.
- Public exact-string searches for `blackvue_gps.cgi`, `blackvue_log.cgi` and
  `blackvue_vod.cgi` returned no vulnerability reports. The DEF CON 32 dashcam
  study covers RTSP stack overflows and command injection in other vendors, not
  these Boa CGI handlers.
- Assessment: high-confidence new vulnerability for K970X Plus v1.003.

### Suggested Remediation

- Replace the unbounded copies with length-limited operations and reject query
  values longer than the destination buffer.
- Validate `strstr()` results before use (especially in `blackvue_vod.cgi`).
- Run the CGI programs as an unprivileged user, enable authentication on the
  web interface, and build the CGIs as PIE with stack protector.

### Disclosure Status

Unpublished. Prepared for coordinated disclosure through the team CVE library;
no public advisory and no CVE assignment yet (`CVE-TBD`).
