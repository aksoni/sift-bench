# Investigative Narrative — SRL-2018 Memory Forensics
**Case:** srl-2018  
**Evidence:** base-rd01-memory.img (MD5: 7bdecf279004928ebc011d08802a401b — verified)  
**Analyst:** claude-code-sift-bench (run4)  
**Report Date:** 2026-05-20 UTC  

---

## Executive Summary

The memory image from host BASE-RD-01 (172.16.6.11) shows a **fully active, multi-stage intrusion** by a threat actor who achieved **Domain Admin-level persistence** beginning no later than 2018-08-30 16:43 UTC. The attacker leveraged WMI-based remote code execution to deploy a PowerShell C2 shell (consistent with PowerShell Empire or similar framework), staged a Meterpreter-compatible implant (`p.exe`) in a masqueraded path, and maintained C2 communications to an internal pivot host (172.16.4.10:8080) for at least **7 days** prior to the forensic capture. All attacker processes ran as `spsql`, a **Domain Admin** account, giving the attacker unrestricted domain-wide access.

Three malfind findings initially flagged as suspicious were **retracted** after self-correction as documented false positive patterns (Outlook COM dispatch table, McAfee AV pre-allocation, .NET CLR heap).

---

## Timeline of Attacker Activity (UTC)

| Timestamp | Event |
|-----------|-------|
| 2018-08-30 13:51:58 | System boot (PID 4 System) |
| 2018-08-30 13:53:44 | User `tdungan` interactive logon (explorer.exe) |
| **2018-08-30 16:43:36** | **WmiPrvSE.exe (PID 2876) spawns blank-cmdline powershell.exe (PID 8712) — WMI execution (T1047)** |
| **2018-08-30 16:43:42** | **32-bit PowerShell C2 shell (PID 5848) activated** — `-Version 5.1 -s -NoLogo -NoProfile` |
| 2018-08-30 18:31:04–35 | rundll32.exe PID 6768 from PS 5848 — injection launcher (exited) |
| 2018-08-30 20:16:57 | LogonUI appears on session 1 — screen lock or second user |
| **2018-08-30 21:40:18–54** | **rundll32.exe PIDs 5452, 5588 — injection launchers** |
| **2018-08-30 22:15:18** | **cmd.exe (PID 5948) launches `c:\windows\temp\perfmon\p.exe` (PID 8260)** |
| 2018-08-30 22:31:57–22:45:30 | rundll32.exe PIDs 2216, 4108 from PS 5848 — injection launchers |
| 2018-08-31 00:56:14–30 | rundll32.exe PID 8148 from PS 5848 — injection launcher |
| 2018-08-31 14:52:29 | New session 3 established (second winlogon) |
| 2018-09-05 12:01:32–40 | rundll32.exe PID 5768 from **p.exe** — p.exe now spawning injectors |
| **2018-09-06 14:58:41** | **rundll32.exe PID 1424 from p.exe** |
| **2018-09-06 17:26:32** | **rundll32.exe PID 7552 from p.exe** |
| 2018-09-06 18:28:30 | F-Response Subject (subject_srv.exe) installed — forensic collection begins |
| 2018-09-06 18:57:16 | Memory image acquired (dc3dd) |

---

## Detailed Findings

### F01 — CONFIRMED | CRITICAL: p.exe Meterpreter Implant

**Finding identified by:** `windows.psscan`, `windows.cmdline`, `windows.filescan`, `windows.dlllist --pid 8260`, `windows.pslist --dump --pid 8260`, YARA scan of dump

`p.exe` (PID 8260) was found at `c:\windows\temp\perfmon\p.exe` — a path that masquerades as the legitimate Windows Performance Monitor directory. The process was launched by cmd.exe (PID 5948) which itself was a child of the PowerShell C2 shell (PID 5848).

YARA scan of the dumped binary (SHA256: `6f9d6ec7e1634f80de9fa5c0792806f7d63960c799be826f296d52af94a06fc0`) confirmed the **Meterpreter named pipe transport** pattern with the string `\\.\pipe\MSSE-7702-server` at offset 0x4a9b9 and the format template `MSSE-%d-` — signatures of the Metasploit Framework's named-pipe inter-stage communication protocol.

The DLL inventory for p.exe shows a complete network and cryptographic stack loaded at process start: `WININET.dll`, `WS2_32.dll`, `DNSAPI.dll`, `IPHLPAPI.DLL`, `bcrypt.dll`, `rsaenh.dll`, `CRYPTSP.dll`, `SSPICLI.DLL`. Additionally, `mpr.dll` and `USER32.dll` were loaded on 2018-09-05 (six days after initial execution), indicating the implant **remained active and extended capabilities over time**.

**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File), T1059.003 (Command and Scripting Interpreter: Windows Command Shell), T1036.005 (Masquerading: Match Legitimate Name or Location)

---

### F02 — CONFIRMED | CRITICAL: WMI-Based Execution via Blank PowerShell

**Finding identified by:** `windows.psscan`, `windows.pstree`, `windows.cmdline`, `windows.getsids --pid 8712`

`powershell.exe` (PID 8712) was spawned by `WmiPrvSE.exe` (PID 2876) — the WMI provider host — with a blank command line at 2018-08-30 16:43:36 UTC. This is the canonical indicator of `Win32_Process.Create` or similar WMI method invocation for remote code execution. The process ran as `spsql` with Domain Admin and High Mandatory Level tokens.

The empty command line is key: legitimate PowerShell invocations from WMI would embed the command in the process parameters; a blank argument string means the WMI payload was passed through an in-memory channel (e.g., WMI subscription or encoded script passed via `CommandLine` that was subsequently cleared).

**MITRE ATT&CK:** T1047 (Windows Management Instrumentation), T1059.001 (PowerShell)

---

### F03 — CONFIRMED | CRITICAL: 32-bit PowerShell Stdin C2 Shell

**Finding identified by:** `windows.psscan`, `windows.cmdline`, `windows.getsids --pid 5848`, `windows.dlllist --pid 5848`

`powershell.exe` (PID 5848) running from `C:\Windows\SysWOW64\` was launched with:
```
"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile
```
The `-s` (stdin) flag is the hallmark of a PowerShell agent — it routes all I/O through stdin/stdout rather than a console, enabling a C2 framework to speak PowerShell through an established communication channel (the parent WMI shell). The 32-bit (SysWOW64) invocation may indicate the attacker needed 32-bit context for specific injection techniques.

`amsi.dll` was present at 0x70f30000 but the attacker very likely bypassed it in-memory (patching `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`). The process has been the root of all attacker operations since 16:43:42 UTC.

**MITRE ATT&CK:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)

---

### F04 — CONFIRMED | HIGH: cmd.exe Executing p.exe from Masqueraded Path

**Finding identified by:** `windows.cmdline`, `windows.pstree`

`cmd.exe` (PID 5948) executed `c:\windows\temp\perfmon\p.exe` at 2018-08-30 22:15:18 UTC. The staging path `c:\windows\temp\perfmon\` is designed to blend with the legitimate Windows Performance Monitor infrastructure. This is a T1036.005 masquerading technique.

**MITRE ATT&CK:** T1059.003 (Windows Command Shell), T1036.005 (Masquerading)

---

### F05 — CONFIRMED | HIGH: Nine Blank-Cmdline rundll32.exe — Shellcode Injection

**Finding identified by:** `windows.psscan`, `windows.pstree`, `windows.cmdline`

Nine `rundll32.exe` processes were spawned by either the PowerShell C2 shell (PID 5848) or the p.exe implant (PID 8260), all with blank command lines, all exiting within 5–30 seconds. Legitimate rundll32 usage requires `rundll32.exe <dllpath>,<export>` — blank arguments mean no DLL was loaded conventionally. The pattern is consistent with spawning rundll32 as a temporary host process for shellcode injection via `WriteProcessMemory` + `CreateRemoteThread`.

The activity spanned 7 days (2018-08-30 through 2018-09-06), showing the attacker repeatedly returned to use the same injection technique.

**MITRE ATT&CK:** T1055.001 (Process Injection: Dynamic-link Library Injection), T1218.011 (System Binary Proxy Execution: Rundll32)

---

### F06 — CONFIRMED | CRITICAL: C2 Beaconing to 172.16.4.10:8080

**Finding identified by:** `windows.netscan`

Three currently ESTABLISHED and seven historical TCP connections to 172.16.4.10:8080 were identified. The connections lack PID attribution, indicating they are owned by injected threads (not a standalone process). Port 8080 is commonly used by Metasploit/Cobalt Strike to blend with HTTP proxy traffic. This is the primary C2 server for the operation.

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1095 (Non-Application Layer Protocol)

---

### F07 — CONFIRMED | CRITICAL: Domain Admin spsql — Full Domain Compromise

**Finding identified by:** `windows.getsids --pid 8260`, `--pid 8712`, `--pid 5848`

All three core attacker processes carry the `spsql` identity with Domain Admins (S-1-5-21-...-512), local Administrators, and High Mandatory Level. The `spsql` account name suggests a SQL service account that was either credential-dumped or compromised through another vector before the memory capture window.

**MITRE ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts)

---

### F08 — CONFIRMED | HIGH: SMB Lateral Movement

**Finding identified by:** `windows.netscan`

Active ESTABLISHED SMB connections to 172.16.4.5:445 and 172.16.7.15:445 indicate lateral movement to at least two additional domain hosts. An inbound SMB connection from 172.16.6.14:65368 to 172.16.6.11:445 is also active, possibly indicating this host is a pivot point.

**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares)

---

### F09 — CONFIRMED (medium confidence) | HIGH: WinRM Lateral Movement

**Finding identified by:** `windows.netscan`, `windows.filescan`

A completed connection to 172.16.5.21:5985 (WinRM) and wsmprovhost.exe CLR usage logs under the `rsydow-a` account profile indicate PowerShell Remoting was used. The `rsydow-a` account may have been used as a pivot identity for WinRM access.

**MITRE ATT&CK:** T1021.006 (Remote Services: Windows Remote Management)

---

### F10 — CONFIRMED (medium confidence) | HIGH: External Connections

**Finding identified by:** `windows.netscan`

CLOSED connections to 52.16.55.11:443 (AWS EU-West-1) and 13.89.220.65:443 (Azure) indicate external staging or C2 callback. These likely represent initial payload download or external reporting endpoints.

**MITRE ATT&CK:** T1071.001, T1102 (Web Service)

---

### F11 — CONFIRMED (medium confidence) | MEDIUM: AD LDAP Reconnaissance

**Finding identified by:** `windows.netscan`

Completed LDAP connection to 172.16.4.4:389 indicates Active Directory enumeration. With Domain Admin credentials, the attacker can query the full AD directory.

**MITRE ATT&CK:** T1018 (Remote System Discovery), T1087.002 (Account Discovery: Domain Account)

---

### F12 — CONFIRMED | LOW: No Registry-Based Persistence (Negative Finding)

**Finding identified by:** `windows.registry.printkey`, `windows.svcscan`

The `spsql` NTUSER.DAT Run and RunOnce keys were empty. svcscan identified no malicious services. The attacker's persistence was achieved through long-lived in-memory processes rather than registry autorun entries. The PowerShell C2 shell (PID 5848) has been alive continuously since 2018-08-30 16:43:42 UTC.

---

### F13 — RETRACTED: OUTLOOK.EXE malfind dtrR → COM Dispatch Table False Positive

The `dtrR` (64 74 72 52) byte pattern flagged by malfind in OUTLOOK.EXE (PID 8128) is a known COM Dispatch Table Record header — a normal Outlook COM automation structure. No PE header, no executable code. This is a documented malfind false positive for all versions of Outlook.

---

### F14 — RETRACTED: UpdaterUI.exe malfind → McAfee AV Pre-Allocation

A single-page RWX null-byte region in McAfee UpdaterUI.exe (PID 6036) has no executable content. McAfee security components pre-allocate RWX regions for runtime code patching during AV signature updates. Known false positive.

---

### F15 — RETRACTED: powershell.exe (PID 8712) malfind → .NET CLR Heap

Three RWX regions in powershell.exe (PID 8712) showing the `ee ff ee ff` pattern are .NET CLR GC heap object header sentinels (0xFFEEFFEE). The CLR runtime allocates managed heap as RWX by design. Known false positive for all .NET/PowerShell processes.

---

## MITRE ATT&CK Summary

| Tactic | Technique | Finding |
|--------|-----------|---------|
| Initial Access | T1078.002 — Valid Accounts: Domain | F07 |
| Execution | T1047 — WMI | F02 |
| Execution | T1059.001 — PowerShell | F02, F03 |
| Execution | T1059.003 — Windows Command Shell | F04 |
| Execution | T1204.002 — Malicious File | F01 |
| Defense Evasion | T1027 — Obfuscated Files | F03 |
| Defense Evasion | T1036.005 — Masquerading | F01, F04 |
| Defense Evasion | T1218.011 — Rundll32 | F05 |
| Defense Evasion | T1055.001 — Process Injection: DLL | F05 |
| Discovery | T1018 — Remote System Discovery | F11 |
| Discovery | T1087.002 — Domain Account Discovery | F11 |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | F08 |
| Lateral Movement | T1021.006 — WinRM | F09 |
| Command & Control | T1071.001 — Web Protocols | F06, F10 |
| Command & Control | T1095 — Non-App Layer Protocol | F06 |
| Command & Control | T1102 — Web Service | F10 |

---

## Recommendations

1. **Immediate:** Isolate BASE-RD-01 (172.16.6.11) from the network. The implant has 3 active C2 connections.
2. **Immediate:** Reset the `spsql` Domain Admin account and all credentials cached on this host (run `lsadump::cache` and similar to enumerate).
3. **Immediate:** Investigate `172.16.4.10` — this is the primary C2 server. If it is a compromised internal host, isolate it.
4. **Short-term:** Audit `172.16.4.5`, `172.16.7.15`, `172.16.5.21`, and `172.16.6.14` for compromise indicators — all had active connections to/from this host.
5. **Short-term:** Audit the `rsydow-a` account — wsmprovhost.exe activity suggests it was used for WinRM lateral movement.
6. **Short-term:** Hunt for `c:\windows\temp\perfmon\` staging directories on all domain-joined systems.
7. **Long-term:** Restrict WMI remote execution to authorized admin workstations. Enable PowerShell Constrained Language Mode and Script Block Logging.
8. **Long-term:** Enable AMSI Integration and EDR coverage on all endpoints to detect PowerShell `-s` stdin agent patterns.

---

## Evidence Integrity

MD5 of `base-rd01-memory.img`: `7bdecf279004928ebc011d08802a401b`  
Matches original dc3dd acquisition hash — chain of custody maintained.  
All analysis outputs written to `./run4_analysis/` and `./run4_exports/` — no evidence files modified.
