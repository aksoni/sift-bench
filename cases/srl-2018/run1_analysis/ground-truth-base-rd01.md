# Ground Truth: base-rd01-memory.img

## Image Metadata

| Field | Value |
|-------|-------|
| Image | base-rd01-memory.img |
| Format | Raw memory dump |
| Size | 3.0 GB |
| OS | Windows 10 x64 (Build 16299) |
| Hostname | BASE-RD-01 |
| Capture Time | 2018-09-06 18:57:17 UTC |
| System Boot | 2018-08-30 13:51:58 UTC |
| Primary User | tdungan |
| Dataset | SANS FOR508 SRL-2018 (Stark Research Labs) |

## Scenario Context

Stark Research Labs (SRL) is a simulated enterprise that suffered an APT intrusion. BASE-RD-01 is an RDP host in the SRL network (IP: 172.16.6.11). This host was not System Zero — it was reached via lateral movement from a previously compromised system.

## Findings

### 1. Compromised Account

The attacker operated under the **spsql** account, a test/service account with Domain Admin privileges. Confirmed via `windows.getsids` on PID 5848:

- SID: S-1-5-21-3445421715-2530590580-3149308974-1193 (spsql)
- Member of: Domain Admins (S-1-5-...-512)
- Integrity Level: High Mandatory Level (S-1-16-12288)
- Member of: Domain Users, Administrators, Network, Authenticated Users

### 2. Initial Access to This Host

**Technique:** WMI lateral movement (MITRE ATT&CK T1047)

The attacker used stolen spsql credentials from another host to remotely execute code via WMI. Evidence:

- PID 2876: `WmiPrvSE.exe` (WMI Provider Host) spawned PowerShell at 16:43:36 UTC
- WmiPrvSE.exe is the legitimate WMI service that handles remote execution requests
- This confirms the attacker already had valid credentials before reaching this host

**Timestamp:** 2018-08-30 16:43:36 UTC (approximately 3 hours after system boot)

### 3. Attack Chain (Process Tree)

```
PID 868  svchost.exe (DCOM Server Process Launcher)
└── PID 2876  WmiPrvSE.exe — 13:52:26 (system service, booted with system)
    └── PID 8712  powershell.exe (64-bit) — 16:43:36 (ATTACKER ENTRY POINT)
        └── PID 5848  powershell.exe (32-bit, SysWOW64) — 16:43:42 (C2 SHELL)
            │   Command: "c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile
            │
            ├── PID 6768  rundll32.exe (SysWOW64) — 18:31:04 → exited 18:31:35 (31s)
            ├── PID 5452  rundll32.exe — 21:40:18 → exited 21:40:23 (5s)
            ├── PID 5588  rundll32.exe — 21:40:42 → exited 21:40:54 (12s)
            ├── PID 5948  cmd.exe — 22:15:18
            │   └── PID 8260  p.exe — 22:15:18 (MALWARE)
            │       Command: c:\windows\temp\perfmon\p.exe
            │       Launched via: cmd.exe /C c:\windows\temp\perfmon\p.exe
            ├── PID 2216  rundll32.exe (SysWOW64) — 22:31:57 → exited 22:32:19 (22s)
            ├── PID 4108  rundll32.exe — 22:45:25 → exited 22:45:30 (5s)
            └── PID 8148  rundll32.exe (SysWOW64) — 00:56:14 Aug 31 → exited 00:56:30 (16s)
```

**Key observations:**
- 64-bit PowerShell spawned 32-bit PowerShell with stealth flags (-NoLogo -NoProfile)
- 32-bit PowerShell was the persistent C2 shell, active for 8+ hours
- Six short-lived rundll32.exe instances (5–31 seconds each) indicate staged DLL execution or reconnaissance
- cmd.exe used /C flag (execute and terminate) to launch p.exe

### 4. Malware: p.exe

| Attribute | Value |
|-----------|-------|
| Path | c:\windows\temp\perfmon\p.exe |
| PID | 8260 |
| Parent | cmd.exe (PID 5948) |
| Created | 2018-08-30 22:15:18 UTC |
| Threads | 2 |
| Staging directory | \Windows\Temp\Perfmon\ (attacker-created) |
| Prefetch | P.EXE-1209D82B.pf (confirms execution on disk) |

**Malfind results:**
- 481-page PAGE_EXECUTE_READWRITE memory region at 0x2be0000–0x2dc0fff
- Large RWX region strongly indicates packed or injected payload

### 5. Additional Malfind Hits

| PID | Process | Assessment |
|-----|---------|------------|
| 8712 | powershell.exe | 3 RWX regions — consistent with attacker C2 shell (SUSPICIOUS) |
| 8260 | p.exe | 481-page RWX region (MALICIOUS) |
| 8128 | OUTLOOK.EXE | 2 RWX regions with "dtrR" signature — known Outlook allocation pattern (FALSE POSITIVE) |
| 6036 | UpdaterUI.exe | 1 RWX region — McAfee updater, likely benign (FALSE POSITIVE) |

### 6. Network Activity

**C2 Communication:**
- Multiple connections from 172.16.6.11 to **172.16.4.10:8080** (ESTABLISHED, CLOSE_WAIT)
- No PID association preserved — owning processes likely exited or kernel disassociated
- Port 8080 commonly used for C2 proxy infrastructure

**Lateral Movement (outbound from this host):**
- 172.16.6.11 → **172.16.7.15:445** (SMB, ESTABLISHED) — file share access or lateral movement
- 172.16.6.11 → **172.16.4.5:3389** (RDP, CLOSED) — RDP to another internal host

**Legitimate services listening:**
- Port 3389 (RDP) — expected for an RDP host
- Various svchost listeners on high ports (49665, 49666)

### 7. Persistence

**Registry Run keys (CurrentVersion\Run):**
- tdungan: OneDrive, Dashlane, DashlanePlugin — all legitimate
- spsql: Empty Run key — no registry-based persistence installed
- No malicious services found via svcscan

**Assessment:** Attacker did not install persistence on this host. Access was maintained through a live PowerShell session, not through boot-persistent mechanisms.

### 8. Additional Artifacts of Interest

- **procdump.exe** found at `\Users\tdungan\AppData\Roaming\Dashlane\6.2.0.12026\procdump.exe` — Sysinternals tool commonly used for credential dumping (LSASS). May be legitimate Dashlane crash reporting, but warrants investigation.
- **spsql NTUSER.DAT** loaded in memory — confirms the spsql account logged into this host

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| Windows Management Instrumentation | T1047 | WmiPrvSE.exe spawned PowerShell remotely |
| PowerShell | T1059.001 | 32-bit PowerShell with -NoLogo -NoProfile as C2 shell |
| Rundll32 | T1218.011 | Six short-lived rundll32 executions from PowerShell |
| Valid Accounts: Domain Accounts | T1078.002 | spsql account with Domain Admin privileges |
| Masquerading: Match Legitimate Name/Location | T1036.005 | p.exe staged in \Windows\Temp\Perfmon\ (legitimate-sounding path) |
| Process Injection | T1055 | 481-page RWX region in p.exe (malfind) |

## Network Map (Partial)

```
172.16.4.5  — RDP target (accessed from this host via port 3389)
172.16.4.10 — C2 server (port 8080, multiple connections)
172.16.6.11 — THIS HOST (BASE-RD-01)
172.16.7.15 — SMB target (accessed from this host via port 445)
```

## Benchmark Scoring Criteria

An accurate analysis of this memory image should identify:

### Must Find (Critical)
- [ ] p.exe as malicious (path, staging directory, RWX memory)
- [ ] spsql as the compromised account
- [ ] WMI lateral movement as the entry vector
- [ ] PowerShell C2 shell with stealth flags
- [ ] C2 connections to 172.16.4.10:8080

### Should Find (Important)
- [ ] Full process tree from WmiPrvSE → powershell → powershell → p.exe
- [ ] Six rundll32 executions as post-exploitation activity
- [ ] Lateral movement indicators (SMB to 172.16.7.15, RDP to 172.16.4.5)
- [ ] Domain Admin privileges on the compromised account

### Should Not Claim (Hallucination Indicators)
- [ ] Claiming this host is System Zero (it was reached via lateral movement)
- [ ] Identifying OUTLOOK.EXE malfind hits as malicious (known false positive)
- [ ] Fabricating network connections not present in netscan output
- [ ] Claiming registry-based persistence when none was found
- [ ] Inventing file contents or tool outputs not supported by evidence

## Source Data

All findings derived from Volatility 3 (v2.27.0) analysis:
- windows.info
- windows.psscan
- windows.pstree
- windows.cmdline
- windows.netscan
- windows.malfind
- windows.svcscan
- windows.registry.printkey
- windows.filescan
- windows.getsids
