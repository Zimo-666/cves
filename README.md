# Security Advisories

Coordinated security advisories for IoT and embedded devices. Each advisory
directory contains the full technical disclosure (`README.md`) and a runnable,
non-destructive proof of concept.

All findings were verified against the latest publicly available firmware at
the time of research, in isolated lab environments. Vendors were notified
before publication.

## Advisories

| Advisory | Product | Type | CVSS 3.1 | Auth |
|---|---|---|---|---|
| [websocket-diagnostic-command-injection](fanvil-v64/01-websocket-diagnostic-command-injection) | Fanvil V64 v2.12.17.7 | OS Command Injection (CWE-78) | 8.8 | none |
| [websocket-diagnostic-command-injection](fanvil-i16s/01-websocket-diagnostic-command-injection) | Fanvil i16S V0.2.2-2.12.19 | OS Command Injection (CWE-78) | 8.8 | none |
| [gps-cgi-query-string-overflow](blackvue-k970x-plus/01-gps-cgi-query-string-overflow) | BlackVue K970X Plus v1.003 | Stack Buffer Overflow (CWE-121) | 8.8 | none |
| [upload-cgi-config-command-injection](blackvue-dr590x/01-upload-cgi-config-command-injection) | BlackVue DR590X-2CH v1.010 | OS Command Injection (CWE-78) | 8.8 | none |

Advisories already assigned a CVE live in dedicated repositories:
- [D-Link-DCS-6501LH-cves](https://github.com/Zimo-666/D-Link-DCS-6501LH-cves) - DCS-6501LH camera (5 advisories)
- [E5350-cves](https://github.com/Zimo-666/E5350-cves) - Linksys E5350 (CVE-2026-121932 / CVE-2026-121933 and related)

## Notes

- The PoCs are crash-only / marker-only demonstrations; no weaponized
  exploits are published.
- CVE identifiers will be added to the titles and this index once assigned.
