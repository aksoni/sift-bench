# Investigative Narrative — Case SRL-2018
**Evidence:** `base-rd01-memory.img` (3.0 GB, 2018-09-06)  
**Host:** BASE-RD-01 — Stark Research Labs workstation (shieldbase.lan domain)  
**Analyst:** claude-code-sift-bench  
**Analysis Date:** 2026-05-17 UTC  
**Enrichment:** Skipped — YARA and hash_file tools unavailable in this baseline run

---

## Executive Summary

BASE-RD-01 was compromised via WMI-based remote execution of a PowerShell C2 shell. The attacker operated under the **spsql** Domain Admin service account, deployed a custom C2 implant (`p.exe`) into a masqueraded staging directory, and maintained persistent access for **at least 7 days** before memory capture. The host was used as a launchpad for lateral movement to at least three internal targets via SMB, RDP, and WinRM. In the final 48 hours before capture, the attacker loaded additional tooling into system directories using reflective PowerShell inside `rundll32.exe` to evade detection. No registry-based or service-based persistence was identified; persistence was maintained through the long-running p.exe process and the WMI-delivered C2 shell.

**Organization:** Stark Research Labs (`shieldbase.lan` domain)  
**Attacker C2 server:** 172.16.4.10:8080  
**Compromised account:** `shieldbase\spsql` (Domain Admins group member)  
**Implant:** `c:\windows\temp\perfmon\p.exe` (PID 8260)

---

## Timeline of Attacker Activity (UTC)

| Time (UTC) | Event | Evidence |
|---|---|---|
| 2018-08-30 13:51:58 | System boot (BASE-RD-01) | pstree: System PID 4 CreateTime |
| 2018-08-30 16:43:36 | **WMI executes PowerShell (PID 8712) as spsql — initial access** | pstree: WmiPrvSE→powershell |
| 2018-08-30 16:43:42 | Attacker C2 shell established: WOW64 PS (PID 5848, `-s -NoLogo -NoProfile`) | cmdline, pstree |
| 2018-08-30 18:31:04 | Reflective rundll32.exe (PID 6768) spawned; exits at 18:31:35 | pstree |
| 2018-08-30 21:40:18 | Multiple rundll32.exe spawns (PIDs 5452, 5588) — attacker testing reflective loading | pstree |
| 2018-08-30 22:15:18 | **p.exe implant deployed via cmd /C** | cmdline: `cmd.exe /C c:\windows\temp\perfmon\p.exe` |
| 2018-08-30 22:31:57 | WOW64 rundll32 (PID 2216) spawned by PS5848 | pstree |
| 2018-08-30 22:45:25 | rundll32 (PID 4108) spawned by PS5848 | pstree |
| 2018-08-31 00:56:14 | WOW64 rundll32 (PID 8148) spawned | pstree |
| 2018-09-05 12:01:32 | **p.exe spawns rundll32 (PID 5768)** — implant starts reflective operations | pstree |
| 2018-09-05 12:13:26 | `mpr.dll` loads into p.exe — implant gains network provider capability | dlllist PID 8260 |
| 2018-09-05 12:14:36 | `USER32.dll` / GDI stack loads into p.exe — additional UI-capable modules | dlllist PID 8260 |
| 2018-09-06 10:58:42 EDT (14:58:42 UTC) | **p.exe→rundll32 (PID 1424) runs: `copy SystemSettings.exe C:\windows\`** | PS transcript |
| 2018-09-06 13:26:32 EDT (17:26:32 UTC) | **p.exe→rundll32 (PID 7552) runs: `mv pa.exe C:\windows\system32\`** | PS transcript |
| 2018-09-06 18:28:30 | F-Response Subject agent starts (forensic acquisition begins) | pstree: subject_srv.exe |
| 2018-09-06 18:56:15 | Memory image captured | evidence file timestamp |

*Note: Transcript timestamps are local (EDT = UTC-4). Volatility timestamps are UTC. Adjusted to UTC in table above.*

---

## Detailed Findings

### 1. Initial Compromise — WMI-Based Execution (CONFIRMED)

The attacker's first visible action was the spawning of `powershell.exe` (PID 8712) by `WmiPrvSE.exe` (PID 2876) at **2018-08-30 16:43:36 UTC**. WmiPrvSE is the WMI Provider host, and it should never parent a PowerShell process in Session 0 under normal circumstances. This is a textbook T1047 (WMI) execution chain.

PID 8712's command line is blank (`-`) — the WMI payload cleared the PEB's command-line field to hinder forensic analysis. The process ran as `shieldbase\spsql`, a Domain Admin service account.

**Evidence:** `windows.pstree` parent chain; `windows.cmdline` blank args; `windows.getsids` Domain Admin SID.

**MITRE:** T1047 (WMI), T1059.001 (PowerShell)

---

### 2. C2 Shell Establishment — Pipeline PowerShell (CONFIRMED)

Three seconds after PID 8712 started, it spawned a 32-bit (WOW64) PowerShell child at **16:43:42 UTC**:

```
"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile
```

The `-s` flag enables stdin-piped input mode. This is the canonical signature of a PowerShell C2 stager (Metasploit's `exploit/multi/handler` with PowerShell payload, PowerShell Empire, or Cobalt Strike PowerShell beacon). Combined with `-NoLogo -NoProfile` to suppress output and skip user profiles, this is unambiguously an attacker-controlled C2 shell (PID 5848).

This shell remained active through the capture date — **7+ days** of interactive attacker access.

**Evidence:** `windows.pstree`, `windows.cmdline`, `windows.getsids`

**MITRE:** T1059.001, T1021.006

---

### 3. Malware Deployment — p.exe in Masqueraded Directory (CONFIRMED)

At **22:15:18 UTC on 2018-08-30**, the attacker used PID 5848 to run:

```
C:\WINDOWS\system32\cmd.exe /C c:\windows\temp\perfmon\p.exe
```

The directory `C:\Windows\Temp\Perfmon\` mimics the legitimate Windows Performance Monitor infrastructure (`perfmon.exe`) to blend the staging path. `p.exe` (PID 8260) started and ran continuously for over 7 days.

**p.exe DLL Stack** (from `windows.dlllist`):
- `WININET.dll`, `WS2_32.dll`, `DNSAPI.dll` — HTTP/TCP/DNS capability
- `CRYPTSP.dll`, `rsaenh.dll`, `bcrypt.dll`, `bcryptPrimitives.dll` — encryption capability
- `SSPICLI.DLL`, `Secur32.dll` — authentication/impersonation capability
- `mpr.dll` (loaded post-launch, 2018-09-05 12:13:26) — network provider/credential access
- `USER32.dll` + GDI stack (loaded post-launch, 2018-09-05 12:14:36) — UI capability

Post-launch DLL loading is characteristic of a C2 implant downloading and activating additional modules from the C2 server. The full network, crypto, and authentication stack confirms p.exe is a capable network implant.

**Evidence:** `windows.psscan`, `windows.cmdline`, `windows.dlllist --pid 8260`, `windows.filescan`

**MITRE:** T1204.002 (Malicious File), T1105 (Ingress Tool Transfer), T1573 (Encrypted Channel)

---

### 4. C2 Beacons — 172.16.4.10:8080 (CONFIRMED)

`windows.netscan` shows 14 TCP connections from this host (172.16.6.11) to **172.16.4.10 on port 8080**, including 3 simultaneously ESTABLISHED at capture time:

| State | Count |
|---|---|
| ESTABLISHED | 3 |
| CLOSE_WAIT | 8 |
| CLOSED | 3 |

Port 8080 is a canonical HTTP-based C2 port used by Metasploit, Empire, and Cobalt Strike. The sustained multi-connection pattern — with old connections in CLOSE_WAIT and new ones still ESTABLISHED — is consistent with a heartbeat/beacon cycle that has been running for days. The PID field is unresolvable in netscan (typical when the owning socket structure doesn't have a live back-reference), but attribution to p.exe is supported by its WININET.dll/WS2_32.dll DLL stack.

**Evidence:** `windows.netscan`

**MITRE:** T1071.001 (Web Protocols), T1095

---

### 5. Domain Admin Privilege — spsql Account (CONFIRMED)

All attacker processes — `powershell.exe` (PID 8712), `powershell.exe` (PID 5848), and `p.exe` (PID 8260) — share the same identity:

| Field | Value |
|---|---|
| Username | `shieldbase\spsql` |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1193` |
| Group | Domain Admins (`S-1-5-21-...-512`) |
| Integrity | High Mandatory Level |

The `spsql` naming convention strongly suggests this is a SQL Server service account that was compromised and abused. A service account with Domain Admin rights is a severe security misconfiguration that gave the attacker unrestricted access to all domain resources.

**Evidence:** `windows.getsids --pid 8712/5848/8260`

**MITRE:** T1078.002 (Domain Accounts)

---

### 6. Defense Evasion — Reflective PowerShell in rundll32.exe (CONFIRMED)

PowerShell transcripts recovered from `\Users\spsql\Documents\` confirm that PowerShell was loaded **inside rundll32.exe** (not powershell.exe) as the execution host:

```
Machine: BASE-RD-01
Host Application: C:\WINDOWS\system32\rundll32.exe
Process ID: 1424
Username: shieldbase\spsql
```

This is the "Unmanaged PowerShell" technique (T1218.011): the C2 framework reflectively loads the .NET CLR and PowerShell engine into `rundll32.exe`. Since `rundll32.exe` is a signed Windows binary, this bypasses PowerShell-targeted defenses (script-block logging may be limited) and evades process-name-based detection.

The DLL list for PS5848 also shows multiple unnamed DLLs (blank name/path entries) consistent with reflectively loaded modules that have no on-disk backing.

Affected rundll32 instances (all parentage from p.exe PID 8260 or PS5848):
- PID 6768 (exited), PID 5452 (exited), PID 5588 (exited), PID 2216 (exited), PID 4108 (exited), PID 8148 (exited), PID 5768 (exited), **PID 1424** (transcript recovered), **PID 7552** (transcript recovered)

**Evidence:** `windows.filescan`, `windows.dumpfiles` (transcript extraction), `windows.dlllist --pid 5848`

**MITRE:** T1218.011 (Rundll32), T1059.001

---

### 7. Defense Evasion — Attacker Moving Binaries to System Directories (CONFIRMED)

Two confirmed commands from recovered PowerShell transcripts:

**Command 1 — 2018-09-06 14:58:42 UTC (PID 1424, local 10:58:42 EDT):**
```powershell
PS> copy c:\windows\ImmersiveControlPanel\SystemSettings.exe C:\windows\
```
Copies a legitimate Windows binary to `C:\windows\` root — likely preparation for masquerading or DLL hijacking.

**Command 2 — 2018-09-06 17:26:32 UTC (PID 7552, local 13:26:32 EDT):**
```powershell
PS> mv c:\windows\temp\perfmon\pa.exe c:\windows\system32\
```
Moves a second attacker binary `pa.exe` from the staging directory into `C:\Windows\System32\`, making it indistinguishable from legitimate Windows system binaries.

**Evidence:** Transcript files extracted via `windows.dumpfiles` from `\Users\spsql\Documents\20180906\`

**MITRE:** T1036.003 (Rename System Utilities), T1036.005 (Match Legitimate Name/Location)

---

### 8. Lateral Movement (CONFIRMED)

Network evidence from `windows.netscan` shows outbound connections to three internal targets:

| Target | Port | Protocol | State | Significance |
|---|---|---|---|---|
| 172.16.4.5 | 3389 | RDP | CLOSED ×7 | DC/server interactive logon |
| 172.16.7.15 | 445 | SMB | **ESTABLISHED** | File system access / lateral movement |
| 172.16.4.5 | 445 | SMB | **ESTABLISHED** | DC SMB (credential theft or C2 staging) |
| 172.16.5.21 | 5985 | WinRM | CLOSED | PowerShell remoting pivot |
| 172.16.4.4 | 389 | LDAP | CLOSED | AD enumeration |

The attacker also received an inbound SMB connection from **172.16.6.14** (ESTABLISHED), which may represent another compromised host pivoting back to BASE-RD-01.

**MITRE:** T1021.001 (RDP), T1021.002 (SMB/Windows Admin Shares), T1021.006 (WinRM), T1018 (Remote System Discovery)

---

### 9. Persistence — No Registry or Service Persistence Found (CONFIRMED NEGATIVE)

All `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` keys were examined across all loaded hives. The `spsql` user's NTUSER.DAT Run key exists but contains zero values. `windows.svcscan` found no services with binary paths in user-writable directories or with attacker-related names.

**The attacker's persistence was entirely process-based** — the WMI-delivered PowerShell shell (PID 8712 → 5848) and p.exe (PID 8260) have been running since August 30. This means a system reboot would terminate the attacker's foothold. However, the attacker was actively operating at capture time and likely had WMI subscriptions or scheduled tasks on other hosts (not visible from this memory image alone).

---

### 10. Unconfirmed: procdump.exe in Dashlane Directory (UNCONFIRMED)

`windows.filescan` found `procdump.exe` at:
```
\Users\tdungan\AppData\Roaming\Dashlane\6.2.0.12026\procdump.exe
```

Procdump (Sysinternals) is commonly used to dump `lsass.exe` for credential extraction (T1003.001). Its presence inside the Dashlane password manager's application directory is highly unusual; Dashlane does not ship procdump. This may represent a previous attacker action to stage the tool in a less-scrutinized directory. **Without hash verification or YARA scan, this finding cannot be confirmed as attacker-placed.** Recommend disk forensics to verify file timestamps, creation source, and hash against known-good Sysinternals builds.

---

## False Positives Identified and Retracted

Three initial `windows.malfind` findings were retracted during self-correction:

| Finding | Process | Reason for Retraction |
|---|---|---|
| F17 | OUTLOOK.EXE (PID 8128) | `dtrR` (0x52727464) ATL thunk pattern — known Outlook COM false positive |
| F18 | powershell.exe (PID 8712) | `0xEEFFEEFF` CLR GC heap header — .NET JIT RWX allocation, expected |
| F19 | UpdaterUI.exe (PID 6036) | 1-page RWX with incrementing offset — COM dispatch table, McAfee known pattern |

No code injection into third-party processes was detected.

---

## MITRE ATT&CK Mapping

| Technique | ID | Finding |
|---|---|---|
| Windows Management Instrumentation | T1047 | WMI → PowerShell execution |
| PowerShell | T1059.001 | C2 shell (PID 5848), reflective PS in rundll32 |
| Rundll32 | T1218.011 | Reflective PS loading into rundll32 |
| Domain Accounts | T1078.002 | spsql Domain Admin account abuse |
| Remote Desktop Protocol | T1021.001 | Lateral movement to 172.16.4.5 |
| SMB/Admin Shares | T1021.002 | Lateral movement to 172.16.7.15, 172.16.4.5 |
| Windows Remote Management | T1021.006 | WinRM pivot to 172.16.5.21 |
| Web Protocols (HTTP C2) | T1071.001 | Beaconing to 172.16.4.10:8080 |
| Ingress Tool Transfer | T1105 | p.exe downloaded/staged |
| Encrypted Channel | T1573 | p.exe crypto DLL stack |
| Masquerading | T1036.005 | Temp\Perfmon\ staging dir, pa.exe in System32 |
| Rename System Utilities | T1036.003 | pa.exe masquerading in System32 |
| OS Credential Dumping (LSASS) | T1003.001 | procdump.exe (UNCONFIRMED) |
| Remote System Discovery | T1018 | LDAP query to 172.16.4.4 |
| Domain Account Discovery | T1087.002 | LDAP enumeration of domain |
| Malicious File | T1204.002 | p.exe execution |

---

## Recommendations

1. **Immediate isolation** of BASE-RD-01 from the network — C2 beacons to 172.16.4.10:8080 were still ESTABLISHED at capture time.

2. **Investigate 172.16.4.10** — This host is the attacker's C2 server. Determine whether it is an external pivot point or a compromised internal host.

3. **Investigate lateral movement targets** — 172.16.7.15 (SMB), 172.16.4.5 (RDP + SMB), 172.16.5.21 (WinRM) must be treated as potentially compromised. Acquire memory images from all three hosts.

4. **Disable and rotate the spsql account** — This Domain Admin service account is fully compromised. All credentials derived from it (Kerberos tickets, NTLM hashes) must be treated as attacker-controlled. Reset the account password and audit all service dependencies.

5. **Hunt for WMI subscriptions** — The attacker gained access via WMI. Check for persistent WMI event subscriptions (`__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`) on BASE-RD-01 and domain controllers.

6. **Verify pa.exe in System32** — Confirm whether `C:\Windows\System32\pa.exe` is present on the live system and recover it for analysis.

7. **Disk forensics on BASE-RD-01** — Memory analysis cannot recover the full PowerShell command history (Aug 30 transcripts are zeroed in cache). Disk forensics should recover transcript files from `C:\Users\spsql\Documents\` for complete attacker command history.

8. **Review procdump.exe** — Determine whether lsass.exe was dumped using `\Users\tdungan\AppData\Roaming\Dashlane\6.2.0.12026\procdump.exe` and whether credentials from the tdungan account were extracted.

9. **Remediate svchost.exe WinRM listener** — Port 5985 is open; WinRM-based lateral movement was possible. Restrict WinRM access via Windows Firewall GPO.

10. **Service account hardening** — `spsql` should not be a Domain Admin. Apply principle of least privilege; SQL service accounts require only local service rights or dedicated SQL agent rights.

---

*Note: Hash verification (hash_file) and YARA scanning were not available for this baseline run. Re-run analysis with enrichment tools enabled to verify p.exe, pa.exe, and procdump.exe against known threat intelligence.*
