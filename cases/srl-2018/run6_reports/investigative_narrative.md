# Investigative Narrative — SRL-2018 Base-RD01
**Case:** SRL-2018 | **Host:** base-rd01 | **Image:** base-rd01-memory.img  
**Analyst:** claude-code-sift-bench (Run 6)  
**Analysis date:** 2026-05-20 UTC  
**Memory capture:** 2018-09-06 18:57:17 UTC (Windows 10 x64 Build 16299)

---

## Executive Summary

A threat actor compromised the `spsql` Domain Admin service account and used WMI-based remote execution to establish a persistent PowerShell C2 shell on base-rd01. The attacker deployed a custom implant (`p.exe`) from a staging directory masquerading as a Windows performance monitoring path, maintained active C2 communications to 172.16.4.10:8080 for at least 7 days, and conducted lateral movement to at least three other hosts (172.16.4.5, 172.16.7.15, 172.16.5.21) via SMB, RDP, and WinRM. A credential access tool (procdump.exe) was staged in the victim user's password manager directory. No registry-based persistence was installed; the attacker relied on a long-running interactive PowerShell session.

**14 CONFIRMED findings. 3 RETRACTED (false positives). 0 UNCONFIRMED.**

**MCP enrichment status:** Both `mcp__hash_file` and `mcp__yara_scan` invoked successfully. p.exe SHA256: `6f9d6ec7e1634f80de9fa5c0792806f7d63960c799be826f296d52af94a06fc0`. Zero YARA matches from operative ruleset on both p.exe and procdump.exe (process dumps rather than raw binaries may affect rule matching; absence of match does not indicate clean).

---

## Timeline of Attacker Activity (UTC)

| Timestamp | Event |
|-----------|-------|
| 2018-08-30 16:43:36 | WMI-based execution: WmiPrvSE.exe (PID 2876) spawns powershell.exe (PID 8712) |
| 2018-08-30 16:43:42 | PS 8712 spawns SysWOW64 powershell.exe (PID 5848) with stealth flags (-s -NoLogo -NoProfile) |
| 2018-08-30 18:31:04 | First rundll32 (PID 6768) spawned from PS 5848; exits at 18:31:35 |
| 2018-08-30 21:40:18 | Second rundll32 (PID 5452) from PS 5848; exits 21:40:23 |
| 2018-08-30 21:40:42 | Third rundll32 (PID 5588) from PS 5848; exits 21:40:54 |
| 2018-08-30 22:15:18 | PS 5848 spawns cmd.exe (PID 5948): `cmd /C c:\windows\temp\perfmon\p.exe` |
| 2018-08-30 22:15:18 | p.exe (PID 8260) executes — C2 implant deployed |
| 2018-08-30 22:31:57 | Rundll32 (PID 2216, SysWOW64) from PS 5848; exits 22:32:19 |
| 2018-08-30 22:45:25 | Rundll32 (PID 4108) from PS 5848; exits 22:45:30 |
| 2018-08-31 00:56:14 | Rundll32 (PID 8148, SysWOW64) from PS 5848; exits 00:56:30 |
| 2018-09-05 12:01:32 | Rundll32 (PID 5768) from p.exe; exits 12:01:40 — implant active 6 days later |
| 2018-09-05 12:13:26 | mpr.dll loaded into p.exe — post-execution capability expansion |
| 2018-09-05 12:14:36 | USER32/GDI32 DLL family loaded into p.exe |
| 2018-09-06 14:58:41 | Rundll32 (PID 1424) from p.exe; exits 14:58:45 |
| 2018-09-06 17:26:32 | Rundll32 (PID 7552) from p.exe; exits 17:26:35 |
| 2018-09-06 18:57:17 | Memory image captured (F-Response forensic collection) |

---

## Detailed Findings

### F01 — Malicious implant p.exe (CONFIRMED / critical)

`p.exe` (PID 8260) was identified at `c:\windows\temp\perfmon\p.exe` — a path designed to mimic the legitimate Windows Performance Monitor directory. The process was spawned by `cmd.exe` (PID 5948) running under the `spsql` account with Domain Admin SID (S-1-5-21-3445421715-2530590580-3149308974-512).

**Enrichment:** Process dump extracted via `windows.pslist --dump --pid 8260` (324K, 0x400000 load address). Hashed via `mcp__hash_file`: SHA256 `6f9d6ec7e1634f80de9fa5c0792806f7d63960c799be826f296d52af94a06fc0`. Scanned via `mcp__yara_scan` against `yara_rules/srl-2018-operative.yar`: 0 matches (process dump format, not raw PE; absence of match is not exculpatory).

**MITRE:** T1204.002, T1036.005

### F02 — WMI-based execution (CONFIRMED / critical)

`powershell.exe` (PID 8712) was spawned by `WmiPrvSE.exe` (PID 2876) at 2018-08-30 16:43:36 UTC. WMI Provider Service (WmiPrvSE.exe) spawning PowerShell is the canonical indicator of WMI-based lateral execution (T1047). This represents the attacker's entry point onto base-rd01 — they executed a WMI command from a remote system that triggered the PS execution chain.

**MITRE:** T1047, T1021.003

### F03 — PowerShell C2 shell with stealth flags (CONFIRMED / critical)

`powershell.exe` (PID 5848) running from `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` (32-bit on 64-bit system — a known evasion technique) with flags `-Version 5.1 -s -NoLogo -NoProfile`. The `-s` flag routes commands via stdin rather than interactive console, the standard mechanism for PowerShell-based C2 shells (Cobalt Strike, Metasploit, Empire). Process active from 2018-08-30 16:43:42 to at least memory capture on 2018-09-06 — an active duration exceeding 7 days. Running as `spsql` with Domain Admin privileges.

**MITRE:** T1059.001, T1078.002

### F04 — C2 channel to 172.16.4.10:8080 (CONFIRMED / critical)

`windows.netscan` shows multiple TCP connections from victim (172.16.6.11) to 172.16.4.10:8080, including two ESTABLISHED connections (ports 49786, 49787, 49788) and multiple CLOSE_WAIT/CLOSED states from earlier sessions. Port 8080 is a common C2 port for HTTP-based beaconing. The orphaned PID (`-`) in netscan is consistent with the C2 connections being managed by p.exe whose socket handles may not have been enumerated at snapshot time.

**MITRE:** T1071.001, T1095

### F05 — spsql account with Domain Admin privileges (CONFIRMED / critical)

`windows.getsids` confirms both `p.exe` (PID 8260) and the PowerShell C2 shell (PID 5848) execute under the `spsql` account (SID S-1-5-21-3445421715-2530590580-3149308974-1193) with membership in Domain Admins (SID -512) and Administrators (-544) at High Mandatory Level. The `spsql` account name suggests an SQL service account — an account class that is frequently over-privileged and less monitored than named user accounts.

**MITRE:** T1078.002

### F06 — Six rundll32.exe instances from PS C2 shell (CONFIRMED / high)

`windows.pstree` and `windows.psscan` confirm six `rundll32.exe` processes spawned by `powershell.exe` (PID 5848) across the intrusion: PIDs 6768 (18:31), 5452 (21:40), 5588 (21:40), 2216 (22:31), 4108 (22:45), 8148 (00:56). All exited within 12–31 seconds. The pattern — short-lived rundll32 children of a C2 shell — is consistent with in-memory payload staging or lateral movement via rundll32 as a LOLBin (Living Off the Land Binary).

**MITRE:** T1218.011

### F07 — SMB and RDP lateral movement to 172.16.4.5 (CONFIRMED / high)

`windows.netscan` shows an ESTABLISHED SMB connection (172.16.6.11:49763 → 172.16.4.5:445) and six CLOSED RDP connections (172.16.6.11 → 172.16.4.5:3389), indicating the attacker moved laterally to 172.16.4.5 using both SMB file access and RDP interactive sessions.

**MITRE:** T1021.002, T1021.001

### F08 — Full attacker process chain (CONFIRMED / critical / synthesis)

The complete attacker execution chain reconstructed from `windows.pstree` and `windows.cmdline`:

```
WmiPrvSE.exe (2876)
  └── powershell.exe (8712) [System32, no cmdline visible, 16:43:36]
        └── powershell.exe (5848) [SysWOW64, -s -NoLogo -NoProfile, 16:43:42]
              ├── rundll32.exe (6768, 5452, 5588, 2216, 4108, 8148) [all exited]
              └── cmd.exe (5948) [/C c:\windows\temp\perfmon\p.exe, 22:15:18]
                    └── p.exe (8260) [c:\windows\temp\perfmon\p.exe, 22:15:18]
                          └── rundll32.exe (5768, 1424, 7552) [all exited]
```

This chain documents WMI-based initial execution → dual-stage PowerShell C2 establishment → implant deployment across a 5.5-hour window, with ongoing tasking for 7+ days.

**MITRE:** T1047, T1059.001, T1059.003, T1204.002

### F09 — p.exe DLL profile: network/crypto stack with post-execution loading (CONFIRMED / high)

`windows.dlllist --pid 8260` shows p.exe loaded a complete network and cryptographic capability stack at process start (22:15:18–22:15:19): WININET.dll (HTTP/HTTPS), WS2_32.dll (Winsock), DNSAPI.dll, IPHLPAPI.DLL, SSPICLI.DLL (NTLM/Kerberos credential relay), rsaenh.dll, bcrypt.dll, CRYPTBASE.dll, bcryptPrimitives.dll.

Critically, mpr.dll was loaded at 2018-09-05 12:13:26 UTC — 5 days, 14 hours after p.exe started — followed by USER32.dll, win32u.dll, GDI32.dll, gdi32full.dll, msvcp_win.dll, and ucrtbase.dll at 12:14:36. Post-execution DLL loading of this scope (network provider + GUI libraries) indicates the implant received new tasking requiring capabilities not loaded at startup. No AMSI.dll observed; no unnamed/anonymous DLLs.

**MITRE:** T1071.001

### F10 — procdump.exe staged in Dashlane password manager directory (CONFIRMED / high)

`windows.filescan` identified `procdump.exe` at `\Users\tdungan\AppData\Roaming\Dashlane\6.2.0.12026\procdump.exe` — inside the legitimate Dashlane password manager application folder. procdump.exe (Sysinternals) is a primary LSASS credential dumping tool (T1003.001). Staging it inside a legitimate application directory is a masquerading technique (T1036.005).

**Enrichment:** Dumped via `windows.dumpfiles --virtaddr 0x8c88b3fd7770` (504K DataSectionObject). Hashed via `mcp__hash_file`: SHA256 `8b87ad368f48a2414834cedafa3caafb9b07d8710699cb6df105e5a8e2616821`. Scanned via `mcp__yara_scan`: 0 matches. No running procdump.exe process visible in psscan — tool was staged but execution not confirmed from memory alone.

**MITRE:** T1003.001, T1036.005

### F11 — Three rundll32.exe instances from p.exe (CONFIRMED / medium)

p.exe (PID 8260) spawned three rundll32.exe processes: PID 5768 (2018-09-05 12:01:32, exited 12:01:40), PID 1424 (2018-09-06 14:58:41, exited 14:58:45), PID 7552 (2018-09-06 17:26:32, exited 17:26:35). All exited within seconds. These executions span a week after initial deployment, confirming long-term C2 tasking through the implant.

**MITRE:** T1218.011

### F12 — SMB lateral movement to 172.16.7.15:445 (CONFIRMED / medium)

ESTABLISHED SMB connection from 172.16.6.11:59352 to 172.16.7.15:445, a different subnet from 172.16.4.5. Indicates base-rd01 was used as a pivot point to reach multiple network segments.

**MITRE:** T1021.002

### F13 — WinRM connection attempt to 172.16.5.21:5985 (CONFIRMED / medium)

CLOSED TCP connection to 172.16.5.21:5985 (WinRM/HTTP) indicates a WinRM lateral movement attempt to a third target host. CLOSED state means the connection completed and terminated gracefully.

**MITRE:** T1021.006

### F14 — No registry-based persistence or malicious services (CONFIRMED / low / negative)

`windows.registry.printkey` on `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` across all loaded hives confirms: the spsql ntuser.dat Run and RunOnce keys contain no entries. tdungan's Run key contains only legitimate entries (OneDrive, Dashlane). `windows.svcscan` output (1,325 lines) contains no services with binaries in user-writable paths (Temp, AppData, Users\\). The attacker maintained access via an interactive PowerShell C2 session rather than installing persistent registry or service mechanisms.

**MITRE:** (none — negative finding)

---

## MITRE ATT&CK Summary

| Technique | ID | Finding |
|-----------|-----|---------|
| Windows Management Instrumentation | T1047 | F02, F08 |
| PowerShell | T1059.001 | F03, F08 |
| Windows Command Shell | T1059.003 | F08 |
| User Execution: Malicious File | T1204.002 | F01, F08 |
| Masquerading: Match Legitimate Name or Location | T1036.005 | F01, F10 |
| Valid Accounts: Domain Accounts | T1078.002 | F03, F05 |
| Application Layer Protocol: Web Protocols | T1071.001 | F04, F09 |
| Non-Application Layer Protocol | T1095 | F04 |
| OS Credential Dumping: LSASS Memory | T1003.001 | F10 |
| Signed Binary Proxy Execution: Rundll32 | T1218.011 | F06, F11 |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | F07, F12 |
| Remote Services: Remote Desktop Protocol | T1021.001 | F07 |
| Remote Services: Windows Remote Management | T1021.006 | F13 |
| Lateral Tool Transfer (WMI) | T1021.003 | F02 |

---

## False Positive Retractions

| ID | Process | Pattern | Reason |
|----|---------|---------|--------|
| F15 | OUTLOOK.EXE (8128) | `64 74 72 52` (dtrR) in RWX region | VSTO/COM IDispatch table marker; documented false positive in all Office processes |
| F16 | UpdaterUI.exe (6036) | Small RWX null page | McAfee Agent binary; null-byte RWX region consistent with security product memory allocation |
| F17 | powershell.exe (8712) | `0xEEFFEEFF` in RWX region | .NET CLR GC heap sentinel; expected in all managed .NET processes |

---

## Recommendations

1. **Immediate containment:** Isolate base-rd01. Revoke and reset the `spsql` account credentials across the domain.
2. **C2 blocking:** Block 172.16.4.10:8080 at the perimeter; investigate that host as the attacker's C2 infrastructure.
3. **Lateral movement scope:** Investigate 172.16.4.5, 172.16.7.15, and 172.16.5.21 for compromise indicators. The SMB and RDP connections suggest credential reuse across these hosts.
4. **Credential assessment:** Assume all credentials accessible to the `spsql` Domain Admin account are compromised. Rotate all service account passwords domain-wide.
5. **Procdump artifact:** Determine whether procdump.exe was executed against LSASS on this or other hosts. Check for LSASS dump files on disk or evidence of credential theft in adjacent systems.
6. **WMI persistence:** Audit WMI subscriptions across the domain — WMI-based initial access may have been established via a persistent WMI event subscription on a remote host.
7. **p.exe binary:** SHA256 `6f9d6ec7e1634f80de9fa5c0792806f7d63960c799be826f296d52af94a06fc0` — submit for threat intelligence cross-reference and deploy as an IOC across EDR/AV platforms.
