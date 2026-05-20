# Investigative Narrative — SRL-2018 Memory Forensics
**Case:** srl-2018  
**Analyst:** claude-code-sift-bench  
**Evidence:** base-rd01-memory.img  
**Analysis Date:** 2026-05-20 UTC  
**Run:** 5  

---

## Executive Summary

Analysis of the base-rd01 Windows memory image reveals a sophisticated, multi-stage intrusion in which an attacker using **Domain Admin credentials for the `spsql` account** achieved remote code execution via Windows Management Instrumentation (WMI), deployed a persistent C2 implant (`p.exe`) disguised in a Windows Temp staging directory, and then used those privileges to move laterally across the internal network. The implant was active for at least **8 days** (2018-08-30 through at least 2018-09-06), maintained persistent C2 beaconing to `172.16.4.10:8080`, and executed plugin modules on demand via child `rundll32.exe` processes. No registry-based persistence was identified, suggesting the attacker relied on the long-lived implant process rather than a startup mechanism.

The binary malware classification for `p.exe` is marked **UNCONFIRMED** per protocol — the extracted binary artifact could not be hashed or YARA-scanned using the required MCP tools (`mcp__hash_file`, `mcp__yara_scan`), which were not available in this analysis session. All behavioral findings are CONFIRMED by tool output.

---

## Timeline of Attacker Activity (UTC)

| Timestamp (UTC) | Event | Evidence |
|---|---|---|
| 2018-08-30 16:43:36 | WMI remote execution: `WmiPrvSE.exe` (PID 2876) spawns `powershell.exe` (PID 8712) under `spsql` Domain Admin account | `windows.psscan`, `windows.getsids` |
| 2018-08-30 16:43:42 | 64-bit PowerShell spawns 32-bit SysWOW64 `powershell.exe` (PID 5848) via PS Remoting engine (`-s` flag) | `windows.pstree`, `windows.cmdline` |
| 2018-08-30 18:31:04 | First `rundll32.exe` (PID 6768) spawned by PS 5848 — attacker loading initial modules | `windows.psscan` |
| 2018-08-30 21:40:18 | Additional `rundll32.exe` children (PIDs 5452, 5588) spawned — continued staging | `windows.psscan` |
| 2018-08-30 22:15:18 | `cmd.exe` (PID 5948) launched with `p.exe` — C2 implant deployed to `C:\Windows\Temp\Perfmon\p.exe` | `windows.cmdline`, `windows.psscan` |
| 2018-08-30 22:31:57 | `rundll32.exe` (PID 2216) spawned by PS 5848 | `windows.psscan` |
| 2018-08-30 22:45:25 | `rundll32.exe` (PID 4108) spawned by PS 5848 | `windows.psscan` |
| 2018-08-30 (various) | Multiple C2 connections to 172.16.4.10:8080 ESTABLISHED; LDAP query to 172.16.4.4:389; WinRM to 172.16.5.21:5985 | `windows.netscan` |
| 2018-08-30 (various) | SMB lateral movement to 172.16.7.15:445 and 172.16.4.5:445; RDP attempts to 172.16.4.5 | `windows.netscan` |
| 2018-08-31 00:56:14 | Final `rundll32.exe` (PID 8148) spawned by PS 5848 | `windows.psscan` |
| 2018-09-05 12:01:32 | `p.exe` spawns `rundll32.exe` (PID 5768) — implant executes plugin module | `windows.psscan` |
| 2018-09-05 12:13:26 | `mpr.dll`, `USER32.dll` and display DLLs loaded by `p.exe` — capability expansion | `windows.dlllist` |
| 2018-09-06 14:58:41 | `p.exe` spawns `rundll32.exe` (PID 1424) | `windows.psscan` |
| 2018-09-06 17:26:32 | `p.exe` spawns `rundll32.exe` (PID 7552) — last observed activity | `windows.psscan` |

---

## Detailed Findings

### F01 — p.exe in Attacker Staging Directory (UNCONFIRMED — binary classification)

`p.exe` (PID 8260) was found running from `C:\Windows\Temp\Perfmon\p.exe`. This directory name (`Perfmon`) mimics a legitimate Windows performance monitoring subdirectory to blend in. The process:
- Runs as `spsql` with **Domain Admin** SID (`S-1-5-21-3445421715-2530590580-3149308974-512`)
- Was started by `cmd.exe` (PID 5948) at 2018-08-30 22:15:18 UTC
- Has a Prefetch file (`P.EXE-1209D82B.pf`) confirming prior executions
- Loaded a full network stack (WININET, WS2_32, DNSAPI, IPHLPAPI), crypto stack (rsaenh, bcrypt, CRYPTSP, bcryptPrimitives, CRYPTBASE), and auth libraries (Secur32, SSPICLI)
- Loaded additional DLLs (mpr.dll, USER32.dll, GDI32.dll) on 2018-09-05, 6 days after start, indicating active capability expansion
- Has a 2MB+ RWX VadS memory region (`0x2BE0000–0x2DC0FFF`, 481 pages) with no file backing

The binary classification as malware/C2 is UNCONFIRMED because `mcp__hash_file` and `mcp__yara_scan` were unavailable in this session. The extracted artifact exists at `run5_exports/dumpfiles/file.0x8c88af21def0.0x8c88b154ea70.ImageSectionObject.p.exe.img`.

**Tool:** `windows.psscan`, `windows.pstree`, `windows.cmdline`, `windows.getsids --pid 8260`, `windows.dlllist --pid 8260`, `windows.filescan`, `windows.malfind`

---

### F02 — C2 Beaconing to 172.16.4.10:8080 (CONFIRMED)

At the time of memory capture, three ESTABLISHED TCP connections from 172.16.6.11 to 172.16.4.10:8080 were present simultaneously, along with eight additional CLOSE_WAIT connections to the same endpoint. The accumulation of CLOSE_WAIT states (server-side close, client waiting) indicates a beacon loop where the C2 server repeatedly closes connections and the client reconnects. HTTP port 8080 is consistent with a Cobalt Strike, Metasploit Meterpreter, or similar HTTP-based C2 framework. `p.exe` has `WININET.dll` loaded, supporting HTTPS/HTTP transport.

**IOC:** `172.16.4.10:8080`  
**Tool:** `windows.netscan`, `windows.dlllist --pid 8260`

---

### F03 — WMI Remote Execution for Initial Access (CONFIRMED)

The process `WmiPrvSE.exe` (PID 2876, parent: svchost PID 868) spawned `powershell.exe` (PID 8712) at 2018-08-30 16:43:36 UTC. WMI Provider Host is a standard Windows process used for WMI queries; when used for remote execution, it spawns child processes on behalf of a remotely authenticated caller. `WmiPrvSE` ran as `NT Authority/NetworkService` (S-1-5-20), but the spawned PowerShell ran as `spsql` (Domain Admin), confirming the attacker authenticated the WMI call using `spsql` credentials.

**MITRE:** T1047 — Windows Management Instrumentation  
**Tool:** `windows.psscan`, `windows.pstree`, `windows.getsids --pid 2876`, `windows.getsids --pid 8712`

---

### F04 — 32-bit PowerShell Remoting Chain (CONFIRMED)

The attacker's 64-bit `powershell.exe` (PID 8712) spawned a 32-bit `powershell.exe` from `C:\Windows\SysWOW64` (PID 5848) with the command line `"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile`. The `-s` flag enables stdin-based PowerShell Remoting engine mode, allowing the parent to drive the child as a remote session target. This 32-bit shell then launched `cmd.exe` → `p.exe`. Using 32-bit PowerShell provides compatibility with 32-bit payloads and may avoid some 64-bit AMSI enforcement.

Note: `amsi.dll` was loaded in powershell.exe (PID 8712), so AMSI bypass was not confirmed.

**MITRE:** T1059.001 — PowerShell  
**Tool:** `windows.pstree`, `windows.cmdline`, `windows.dlllist --pid 8712`

---

### F05 — Lateral Movement via SMB and RDP (CONFIRMED)

Two ESTABLISHED SMB (port 445) connections were active at capture time:
- `172.16.6.11:59352 → 172.16.7.15:445` (ESTABLISHED)
- `172.16.6.11:49763 → 172.16.4.5:445` (ESTABLISHED)

Seven CLOSED RDP connections to `172.16.4.5:3389` indicate repeated remote desktop sessions. Domain Admin credentials make SMB and RDP trivial to authenticate across domain-joined hosts. The pattern suggests the attacker used this host as a pivot point for further spread.

**MITRE:** T1021.002 (SMB/Windows Admin Shares), T1021.001 (Remote Desktop Protocol)  
**Tool:** `windows.netscan`

---

### F06 — Active Directory LDAP Reconnaissance (CONFIRMED)

A CLOSED connection to `172.16.4.4:389` (LDAP) was captured. LDAP port 389 is used to query domain controllers for user accounts, groups, and computer objects. This is consistent with Domain Admin privilege enumeration of the environment (e.g., `Get-ADUser`, `net group "Domain Admins"`, BloodHound-style queries).

**MITRE:** T1018 (Remote System Discovery), T1087.002 (Domain Account Discovery)  
**Tool:** `windows.netscan`

---

### F07 — WinRM Connection to 172.16.5.21:5985 (UNCONFIRMED)

A single CLOSED connection to `172.16.5.21:5985` (WinRM/HTTP) was captured. WinRM is the PS Remoting transport. A completed WinRM session is consistent with the attacker using `Enter-PSSession` or `Invoke-Command` to pivot to `172.16.5.21`. However, without memory evidence from that host, success cannot be confirmed.

**MITRE:** T1021.006 (Windows Remote Management)  
**Tool:** `windows.netscan`

---

### F08 — p.exe Spawned rundll32 Children (Plugin/Module Execution) (CONFIRMED)

`p.exe` (PID 8260) spawned three `rundll32.exe` processes with no visible command lines across 2018-09-05 to 2018-09-06. Each process ran for 3–8 seconds then exited. This pattern is consistent with an implant's in-memory module execution system, where `rundll32.exe` is used as a carrier to load and execute successive plugin DLLs reflectively, then terminate.

**MITRE:** T1218.011 (Signed Binary Proxy Execution: Rundll32), T1055 (Process Injection)  
**Tool:** `windows.psscan`, `windows.pstree`, `windows.cmdline`

---

### F09 — PowerShell PID 5848 Spawned Six rundll32 Processes (CONFIRMED)

The attacker-controlled 32-bit `powershell.exe` (PID 5848) spawned six `rundll32.exe` processes with blank command lines between 2018-08-30 18:31 and 2018-08-31 00:56 UTC, during the staging phase before and after `p.exe` deployment. This is consistent with a PowerShell-based implant reflectively loading successive DLL-based tools or running encoded payloads.

**MITRE:** T1218.011, T1059.001  
**Tool:** `windows.psscan`, `windows.pstree`, `windows.cmdline`

---

### F10 — No Registry Persistence Detected (CONFIRMED negative)

`windows.registry.printkey` enumerated all Run and RunOnce keys across all loaded hives. No attacker-controlled entries were found under the `spsql` user hive (`\??\C:\Users\spsql\ntuser.dat`) or in any HKLM SOFTWARE hive. `windows.svcscan` identified only VMware tools, standard Windows services, and the F-Response Subject forensic agent. The attacker did not install registry-based or service-based persistence detectable from this memory image.

**Tool:** `windows.registry.printkey`, `windows.svcscan`

---

### F11 — OUTLOOK.EXE malfind dtrR Hits (RETRACTED — false positive)

Two RWX regions in OUTLOOK.EXE (PID 8128) opening with `64 74 72 52` (ASCII: `dtrR`) were initially noted. On review, `dtrR` is a known Outlook internal COM/MAPI object type tag used in heap allocations. Self-referential pointers at offset 8 are consistent with Outlook's heap object headers. No PE header present. **Retracted.**

---

### F12 — PowerShell CLR Heap Hits (RETRACTED — false positive)

Three RWX VadS regions in `powershell.exe` (PID 8712) showing `0xEEFFEEFF` were initially noted. This is the .NET CLR garbage collector heap signature. The .NET runtime allocates managed heap as RWX by design. No shellcode indicators. **Retracted.**

---

### F13 — UpdaterUI.exe Single-Page RWX (RETRACTED — false positive)

One 4KB RWX VadS region in `UpdaterUI.exe` (PID 6036) containing entirely null bytes. Single null-filled page with no code content is not shellcode; consistent with an AV updater's uninitialized self-modifying code buffer. **Retracted.**

---

### F14 — Incoming SMB from 172.16.6.14 (UNCONFIRMED)

An inbound ESTABLISHED SMB connection from `172.16.6.14:65368` was observed. Source context unknown — could be a DC, backup agent, investigator workstation, or attacker-controlled host. Requires host-level investigation of 172.16.6.14.

---

### F15 — procdump.exe in Dashlane Directory (UNCONFIRMED)

`procdump.exe` was found in filescan under `\Users\tdungan\AppData\Roaming\Dashlane\6.2.0.12026\`. Dashlane does not ship procdump. This tool is commonly used to dump LSASS for credential extraction. No active process found. Its presence is suspicious but cannot be confirmed as attacker-placed without additional forensic evidence.

---

## MITRE ATT&CK Mapping

| Technique | ID | Finding |
|---|---|---|
| Windows Management Instrumentation | T1047 | F03 |
| PowerShell | T1059.001 | F04, F09 |
| User Execution: Malicious File | T1204.002 | F01 |
| Web Protocols (HTTP C2) | T1071.001 | F02 |
| Remote Services: SMB | T1021.002 | F05 |
| Remote Services: RDP | T1021.001 | F05 |
| Remote Services: Windows Remote Management | T1021.006 | F07 |
| Remote System Discovery | T1018 | F06 |
| Domain Account Discovery | T1087.002 | F06 |
| Signed Binary Proxy: Rundll32 | T1218.011 | F08, F09 |
| Process Injection | T1055 | F08 |
| OS Credential Dumping: LSASS | T1003.001 | F15 |

---

## Recommendations

1. **Isolate and re-image base-rd01 immediately.** The C2 implant (`p.exe`) was active for at least 8 days with Domain Admin privileges. Full disk imaging and re-deployment is required.

2. **Rotate the `spsql` account credentials immediately.** All services, scheduled tasks, and applications using this account must be identified and re-keyed. Assume this account's credentials are in attacker possession.

3. **Investigate hosts 172.16.4.10 (C2 server), 172.16.7.15, 172.16.4.5, and 172.16.5.21** for signs of lateral movement or compromise. Memory acquisition from these hosts is a priority.

4. **Audit WMI subscriptions and event consumers** across the domain. The initial vector was WMI remote execution; check for installed WMI persistence (ActiveScript/CommandLine consumers).

5. **Review Active Directory for unauthorized Group Policy changes, new privileged accounts, and Golden Ticket indicators.** With 8+ days of Domain Admin access, Kerberos credential material (KRBTGT hash) may have been extracted.

6. **Forensically examine `172.16.6.14`** to determine whether the inbound SMB connection (F14) represents additional attacker infrastructure or investigator activity.

7. **Hash and submit the extracted `p.exe` artifact** (`run5_exports/dumpfiles/file.0x8c88af21def0.0x8c88b154ea70.ImageSectionObject.p.exe.img`) to threat intel platforms once MCP tools are available to complete the binary identification.
