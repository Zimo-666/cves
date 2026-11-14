# [CVE-2026-121932] Linksys E5350 V1.0.00.037 Missing Authentication / OS Command Injection (CWE-306 / CWE-78)

## VulDB Submission Fields

- Vendor: Linksys
- Product: E5350
- Version or Commit: V1.0.00.037
- Vulnerability: Missing Authentication / OS Command Injection (CWE-306 / CWE-78)
- Advisory / Exploit URL: https://github.com/Zimo-666/cves/tree/main/linksys-e5350/01-wizard-apply-preauth-command-injection
- Description:

```
A missing authentication vulnerability was discovered in Linksys E5350 firmware v1.0.00.037 (latest release; product is end-of-life). While the router is in factory/setup-wizard state (wizard_finish not set: out-of-box or after factory reset, before the owner completes initial setup), the URL /wizard/apply.cgi is served without any authentication and is dispatched by the same 86-entry action table as the authenticated /apply.cgi. This exposes the Diagnostics start_ping/start_traceroute actions, whose ping_ip/traceroute_ip parameters are stored in NVRAM verbatim and executed unsanitized via system() by the diag_pingbutton/diag_tracertbutton services, to unauthenticated remote attackers, yielding root command execution. The service blacklist blocks only space, '|' and '>', so ${IFS} supplies whitespace and multi-command injection works. Reproduction (no credentials): POST /wizard/apply.cgi with submit_button=Diagnostics&submit_type=start_ping&ping_ip=y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y returns HTTP 200 with the Diagnostics page; the injected commands execute (marker file created; the identical chain via the authenticated path was syscall-traced: execve("/bin/sh", {"sh","-c","ping -c 5 -s 64 -o /tmp/ping.log <payload> &"})). Boundary controls: the same POST to /apply.cgi in wizard state returns 302 to index.asp (blocked as designed), and after setup completion /wizard/apply.cgi requires authentication. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: Linksys E5350 Pre-Auth OS Command Injection via /wizard/apply.cgi in Factory State

## Summary
A missing-authentication vulnerability was discovered in Linksys E5350 firmware v1.0.00.037 (latest available; product is EOL). While the router is in factory/setup-wizard state (`wizard_finish` not set — out-of-box or after factory reset, before the owner completes initial setup), the URL `/wizard/apply.cgi` is served without any authentication and is dispatched by the *same* 86-entry action table as the authenticated `/apply.cgi`. This exposes the Diagnostics `start_ping`/`start_traceroute` actions — whose `ping_ip`/`traceroute_ip` parameters are executed unsanitized via `system()` — to unauthenticated remote attackers, yielding root command execution.

## Affected Product
- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest release; device is end-of-life)

## Vulnerability Details
- Type: CWE-306 (Missing Authentication for Critical Function) chained with CWE-78 (OS Command Injection)
- Root Cause:
 - mime handler table (httpd, 0x4966c0) entry 18 maps `*wizard/apply.cgi*` to the same POST handler (0x430bc4) as `apply.cgi`. In wizard state, the httpd whitelist (index.asp, SysInfo.htm, close_wizard.cgi, session.cgi, sign.cgi, `wizard/*`, static assets) is served pre-auth; all non-whitelisted URLs are redirected (302) to index.asp.
 - The only gate on the action dispatcher, `FUN_0042c8a0(submit_button)`, is an `[A-Za-z0-9._]` character whitelist — not an authorization check.
 - The Diagnostics handlers store `ping_ip`/`traceroute_ip` to NVRAM verbatim; the service daemons (`diag_pingbutton`/`diag_tracertbutton`, triggered via `killall -HUP nvram_daemon` → `start_single_service()` in librc.so) build a shell command containing the raw value and call `system()`. The character blacklist does not block `;`, `$`, `&`, `(`; `${IFS}` replaces whitespace.

## Proof of Concept (non-destructive)
Precondition: router in factory/wizard state. **No credentials, no session.**

```
POST /wizard/apply.cgi HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded

submit_button=Diagnostics&submit_type=start_ping&change_action=gozila_cgi&gui_action=Apply&commit=1&ping_times=5&ping_size=64&ping_ip=y%3Bcd%24%7BIFS%7D..%3Bcd%24%7BIFS%7Dtmp%3Btouch%24%7BIFS%7De5350_pwned2%3By
```

Observed on rehosted firmware (wizard_finish=0, empty credential store):
- HTTP 200 with the 28,748-byte Diagnostics page (no authentication challenge).
- nvram store: `SET ping_ip=y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y`
- marker file `/tmp/e5350_pwned2` created by the injected shell commands
 (identical execution chain to the authenticated variant, for which a syscall
 trace captured the `execve("/bin/sh", {"sh","-c","ping ... <payload> &"})`).
- Boundary control: the identical POST to `/apply.cgi` (no `wizard/` prefix) in the
 same state returns `HTTP 302 -> /index.asp` (blocked as designed); after setup
 completion (`wizard_finish=1`), `/wizard/apply.cgi` requires authentication.

## Impact
An unauthenticated attacker on the LAN (or WAN, if reachable during setup) gains root command execution on a factory-fresh or freshly-reset router before the owner has set any password — no user interaction needed beyond the device awaiting initial setup. The setup window is also the moment ISP-deployed or replacement units are most exposed.

## CVSS 3.1
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **7.5** (pre-auth root RCE; AC:H reflects the factory-state precondition)

## Discovery

Vendor notified: yes.

## Proof of Concept

See the poc file(s) in this directory.
