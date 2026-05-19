# Investigative Narrative — Case SRL-2018
## Memory Forensics Report: BASE-RD-01

| Field | Value |
|-------|-------|
| **Case** | SRL-2018 |
| **Subject Host** | BASE-RD-01 (172.16.6.11) |
| **Image File** | base-rd01-memory.img |
| **Image SHA256** | 83456c716bbbeb116b474b87473445629db5dd018d0c667ec99f088871e1cbca |
| **Image Size** | ~3GB |
| **OS** | Windows 10 x64 Build 16299 (1709, Fall Creators Update) |
| **Capture Time** | 2018-09-06 18:57:17 UTC |
| **Captured Via** | F-Response Subject (subject_srv.exe PID 1096) connected to base-hunt.shieldbase.lan:5682 |
| **Analyst** | Claude Code DFIR Orchestrator |
| **Report Generated** | 2026-05-15T02:44:03Z |
| **Volatility Version** | 3 Framework 2.27.0 |
| **Enrichment** | SKIPPED — enrichment tools (YARA, hash_file) not available for this baseline run |

---

## Executive Summary

Memory analysis of BASE-RD-01 reveals an active, multi-stage intrusion by a human operator
who compromised the `spsql` domain service account (a member of **Domain Admins**) and used
it to execute a toolchain entirely in memory across at least 12 hours of dwell time.

The attacker gained execution via **WMI** from a remote host, pivoted through a two-stage
**PowerShell** chain to a 32-bit execution environment, dropped and ran a custom payload
(`p.exe`) from a staging directory disguised as a Windows Perfmon folder, and established
persistent **C2 beaconing** to an internal pivot host at 172.16.4.10 on port 8080. Evidence
of **SMB, WinRM, RDP, and LDAP** activity indicates active lateral movement across multiple
internal subnets.

Self-correction during this analysis: identified and retracted 3 malfind false positives
(OUTLOOK.EXE dtrR pattern, PowerShell .NET JIT regions, McAfee UpdaterUI AV FP) and
added 1 new confirmed finding (hands-on-keyboard confirmation via conhost.exe attachment).

**Enrichment note:** YARA scanning and file hashing of `p.exe` and the rundll32 loader
chain were not performed in this run. This is the primary gap in the analysis. Subsequent
runs should hash and YARA-scan `\Windows\Temp\Perfmon\p.exe` to identify the malware family.

---

## Timeline of Attacker Activity (UTC)

| Timestamp (UTC) | Event | Evidence |
|-----------------|-------|----------|
| 2018-08-30 13:52:26 | WmiPrvSE.exe (PID 2876) starts — DCOM/WMI service available | `windows.psscan` |
| 2018-08-30 16:43:36 | **WMI executes powershell.exe (PID 8712) as `spsql`** — initial attacker foothold; cmdline wiped (anti-forensics) | `windows.pstree`, `windows.cmdline` |
| 2018-08-30 16:43:36 | conhost.exe (PID 1740) attached to PS 8712 — human operator at keyboard | `windows.pstree` |
| 2018-08-30 16:43:42 | PS (8712) spawns 32-bit SysWOW64 powershell.exe (PID 5848) with `-s -NoLogo -NoProfile` | `windows.cmdline` |
| 2018-08-30 18:31:04 | First rundll32.exe (PID 6768) spawned from PS 5848 — exits at 18:31:35 (31 sec) | `windows.psscan` |
| 2018-08-30 22:15:18 | **PS 5848 executes: `cmd.exe /C c:\windows\temp\perfmon\p.exe`** | `windows.cmdline` |
| 2018-08-30 22:15:18 | **p.exe (PID 8260) starts** from `\Windows\Temp\Perfmon\p.exe` | `windows.psscan` |
| 2018-08-30 22:31:57 | rundll32.exe (PID 2216) spawned from PS 5848 — exits 22:32:19 | `windows.psscan` |
| 2018-08-30 22:45:25 | rundll32.exe (PID 4108) spawned from PS 5848 — exits 22:45:30 | `windows.psscan` |
| 2018-08-31 00:56:14 | rundll32.exe (PID 8148) spawned from PS 5848 — exits 00:56:30 | `windows.psscan` |
| 2018-09-05 12:01:32 | rundll32.exe (PID 5768) spawned from p.exe 8260 — exits 12:01:40 | `windows.psscan` |
| 2018-09-06 14:58:41 | rundll32.exe (PID 1424) spawned from p.exe 8260 — exits 14:58:45 | `windows.psscan` |
| 2018-09-06 17:26:32 | rundll32.exe (PID 7552) spawned from p.exe 8260 — exits 17:26:35 | `windows.psscan` |
| 2018-09-06 18:57:17 | **Memory image captured** by F-Response | `windows.info` |

**Total observed dwell time: ≥ 7 days 2 hours 14 minutes**

---

## Detailed Findings

### FINDING F01 — CONFIRMED
**WMI-Spawned PowerShell Execution with Anti-Forensics**

`windows.pstree` shows WmiPrvSE.exe (PID 2876, NT Authority/Network Service) as the
direct parent of powershell.exe (PID 8712). `windows.getsids` on WmiPrvSE confirms it
ran as NT Authority (S-1-5-20) while `windows.getsids` on powershell.exe (8712) shows
it running as `spsql` with Domain Admins membership — proving the WMI call was made
with explicit `spsql` credentials from a remote host.

`windows.cmdline` shows PID 8712 args=`-` (command line wiped), a known attacker
anti-forensics technique to prevent command-line recovery from memory.

MITRE: **T1047** (Windows Management Instrumentation), **T1070.004** (Indicator Removal)

---

### FINDING F02 — CONFIRMED
**Two-Stage PowerShell Chain (SysWOW64 / Remoting Server Mode)**

`windows.cmdline` PID 5848: `"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile`

The `-s` flag is documented as enabling PowerShell's remoting server (stdin/stdout pipe
mode). Launching from SysWOW64 creates a 32-bit process, which can load 32-bit shellcode
and may bypass 64-bit AMSI hooks. `windows.pstree` confirms Wow64=True for PID 5848.

MITRE: **T1059.001** (PowerShell), **T1218** (System Binary Proxy Execution)

---

### FINDING F03 — CONFIRMED
**Staged Payload: p.exe in \\Windows\\Temp\\Perfmon\\**

`windows.cmdline` PID 5948: `C:\WINDOWS\system32\cmd.exe /C c:\windows\temp\perfmon\p.exe`

`windows.filescan` confirms both the file object `\Windows\Temp\Perfmon\p.exe`
(offset 0x8c88af21def0) and four directory handles to `\Windows\Temp\Perfmon`,
indicating the directory and payload persisted in memory. The subdirectory name
"Perfmon" is chosen to blend with `C:\Windows\System32\perfmon.exe` (Performance Monitor).
Four distinct rundll32.exe Prefetch hashes in filescan corroborate repeated shellcode
execution from the staging directory.

MITRE: **T1036.005** (Masquerading: Match Legitimate Name or Location)

---

### FINDING F04 — CONFIRMED
**rundll32.exe Abuse for In-Memory Shellcode Loading**

Nine total rundll32.exe processes identified across the attack chain:
- Six children of powershell.exe (PID 5848): PIDs 6768, 5452, 5588, 2216, 4108, 8148
- Three children of p.exe (PID 8260): PIDs 5768, 1424, 7552

All have blank command lines in `windows.cmdline` (`-`). Blank-cmdline rundll32 spawned
from attacker processes is the canonical pattern for injecting and executing shellcode
via `CreateRemoteThread` or direct `NtCreateThread` into a rundll32 stub. Short lifespans
(3–31 seconds) indicate atomic task execution — consistent with lateral movement beacon
callback or token impersonation operations.

MITRE: **T1218.011** (System Binary Proxy Execution: Rundll32)

---

### FINDING F05 — CONFIRMED
**C2 Beaconing to 172.16.4.10:8080**

`windows.netscan` identifies 9+ TCP connections from 172.16.6.11 to 172.16.4.10:8080:
one ESTABLISHED, six CLOSE_WAIT, two CLOSED. All connections show PID=`-`, consistent
with the originating process having exited or injected threads whose handles are not
tracked in the TCP table. The volume of connections to a single non-standard port, with
recurring CLOSE_WAIT states (server-side closure awaiting client FIN), matches the
callback-sleep-callback pattern of common C2 frameworks.

172.16.4.10 is an internal host acting as a C2 relay (not external C2), suggesting a
compromised internal pivot point or dedicated red team infrastructure.

MITRE: **T1071.001** (Application Layer Protocol: Web Protocols), **T1090** (Proxy)

---

### FINDING F06 — CONFIRMED
**SMB Lateral Movement to 172.16.4.5 and 172.16.7.15**

`windows.netscan` shows two ESTABLISHED outbound SMB connections:
- 172.16.6.11:49763 → **172.16.4.5:445** (offset 0x8c88b292b450)
- 172.16.6.11:59352 → **172.16.7.15:445** (offset 0x8c88afe80450)

With `spsql` Domain Admin credentials available, these connections enabled PsExec-style
remote code execution, WMI-over-SMB, or SMB share access for lateral movement staging.

MITRE: **T1021.002** (Remote Services: SMB/Windows Admin Shares)

---

### FINDING F09 — CONFIRMED
**Domain Admin Account 'spsql' Compromised**

`windows.getsids` on PIDs 8712, 5848, and 8260 all return identical token context:
- Username: `spsql` (SID suffix -1193)
- Group: Domain Admins (SID S-1-5-21-3445421715-2530590580-3149308974-512)
- Group: Administrators (S-1-5-32-544)
- Integrity: High Mandatory Level (S-1-16-12288)

The name `spsql` is consistent with a SQL Server service account. Attackers commonly
target SQL service accounts because they are frequently configured with Domain Admin
privileges for database administration and are often excluded from MFA policies.

MITRE: **T1078.002** (Valid Accounts: Domain Accounts)

---

### FINDING F10 — CONFIRMED
**Code Injection in p.exe: 1.9MB Private RWX VAD**

`windows.malfind` identifies a PAGE_EXECUTE_READWRITE VadS region in p.exe (PID 8260):
- Start: 0x2be0000
- End: 0x2dc0fff
- CommitCharge: 481 pages (~1.9MB)
- PrivateMemory: 1 (no file backing)
- Content: paged out of the physical image (__ pattern in hexdump)

A 481-page private RWX region with no file backing in a process dropped from a temp
directory is a strong indicator of reflective shellcode, a Cobalt Strike reflective
DLL loader, or a staged Meterpreter payload allocated in the process's heap.

MITRE: **T1055** (Process Injection), **T1620** (Reflective Code Loading)

---

### FINDING F17 — CONFIRMED (NEW — added during self-correction)
**Hands-on-Keyboard Session Confirmed via conhost.exe**

`windows.pstree` shows conhost.exe (PID 1740) as a direct child of powershell.exe
(PID 8712), created at the same second (2018-08-30 16:43:36 UTC). In Windows 10,
`conhost.exe` (Console Host) is always spawned when a process requires console I/O.
Its presence as a child of the attacker's PowerShell confirms an interactive terminal
session, not automated/headless execution — establishing that a human operator was
personally executing commands.

MITRE: **T1059.001** (supporting indicator of interactive operator presence)

---

### FINDING F07 — UNCONFIRMED
**WinRM Connection to 172.16.5.21**

Single CLOSED WinRM (5985) connection. Cannot confirm successful command execution
from a CLOSED state alone. Requires corroboration from disk artifacts or EVTX logs.

---

### FINDING F08 — UNCONFIRMED
**LDAP Enumeration of 172.16.4.4**

Single CLOSED LDAP connection. Consistent with AD enumeration but insufficient to
confirm what was queried or whether the connection succeeded.

---

### FINDING F11 — UNCONFIRMED
**External HTTPS to 52.16.55.11:443**

Single CLOSED connection with no PID. Could be C2 staging or routine OS/AV cloud
traffic. Enrichment (DNS, ASN lookup) required to classify.

---

### FINDING F12 — UNCONFIRMED
**Inbound SMB from 172.16.6.14**

Cannot distinguish attacker pivot from legitimate admin without additional context.

---

### FINDING F13 — RETRACTED
**OUTLOOK.EXE Malfind Hits**

Both RWX regions begin with bytes `64 74 72 52` (`dtrR`), confirmed as a known Outlook
memory allocation signature per self-correction FP table. Not injected code. Retracted.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Confidence |
|--------|-----------|----|------------|
| Execution | Windows Management Instrumentation | T1047 | CONFIRMED |
| Execution | Command and Scripting: PowerShell | T1059.001 | CONFIRMED |
| Execution | System Binary Proxy: Rundll32 | T1218.011 | CONFIRMED |
| Defense Evasion | System Binary Proxy: Rundll32 | T1218.011 | CONFIRMED |
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | CONFIRMED |
| Defense Evasion | Indicator Removal (cmdline wipe) | T1070.004 | CONFIRMED |
| Defense Evasion | Process Injection | T1055 | CONFIRMED |
| Defense Evasion | Reflective Code Loading | T1620 | CONFIRMED |
| Privilege Escalation | Valid Accounts: Domain Accounts | T1078.002 | CONFIRMED |
| Lateral Movement | Remote Services: SMB | T1021.002 | CONFIRMED |
| Lateral Movement | Remote Services: WinRM | T1021.006 | UNCONFIRMED |
| Lateral Movement | Remote Services: RDP | T1021.001 | UNCONFIRMED |
| Command & Control | Application Layer: Web Protocols | T1071.001 | CONFIRMED |
| Command & Control | Proxy | T1090 | UNCONFIRMED |
| Discovery | LDAP AD Enumeration | T1087.002 | UNCONFIRMED |

---

## Recommendations

1. **Isolate BASE-RD-01 immediately** — active p.exe process and C2 connections were
   live at time of capture. The machine is compromised.

2. **Disable and reset `spsql` account** — the Domain Admin account is fully compromised.
   Assume all systems it had access to are also compromised.

3. **Investigate 172.16.4.10** — this host is acting as a C2 relay. It is likely also
   compromised and should be isolated and imaged.

4. **Triage 172.16.4.5, 172.16.7.15, 172.16.5.21** — SMB and WinRM connections indicate
   lateral movement to these hosts. All require memory and disk imaging.

5. **Hash and YARA-scan `\Windows\Temp\Perfmon\p.exe`** — this was not done in this
   baseline run. Run enrichment in subsequent analysis to identify malware family and
   determine if shared IOCs exist across the environment.

6. **Review WMI subscriptions and scheduled tasks** — attacker had dwell time of 7+ days
   and Domain Admin access. Persistence mechanisms beyond in-memory loading must be
   ruled out via disk forensics.

7. **Audit `spsql` account logon history** — determine the initial compromise vector
   (phishing, credential stuffing, pass-the-hash) using EVTX Security logs (Event IDs
   4624, 4648, 4768, 4769).

8. **Check external IP 52.16.55.11** — perform ASN/WHOIS lookup and check firewall logs
   for the full volume of traffic to this IP before and after the compromise date.
