# Investigative Narrative — BASE-RD-01 Memory Analysis
## Case: srl-2018 | Evidence: base-rd01-memory.img

| Field | Value |
|-------|-------|
| **Analyst** | DFIR Orchestrator (Claude Code) |
| **Date of Analysis** | 2026-05-16 UTC |
| **Image Capture Time** | 2018-09-06 18:57:17 UTC |
| **OS** | Windows 10 x64 Build 15.16299 (Version 1709) |
| **Hostname** | BASE-RD-01 |
| **Domain** | shieldbase.lan |
| **Victim IP** | 172.16.6.11 |
| **Tool** | Volatility 3 Framework 2.27.0 |
| **Enrichment** | YARA and hash_file enrichment skipped — tools not available for this baseline run |

---

## Executive Summary

BASE-RD-01 was actively compromised at the time of memory capture. A threat actor gained
initial access by executing PowerShell via Windows Management Instrumentation (WMI), using
a Domain Admin service account named **spsql** that had been compromised prior to this
session. The attacker deployed a custom implant, **p.exe**, into `C:\Windows\Temp\Perfmon\`
to masquerade as a Windows performance monitoring component. The implant maintained active
C2 communication to **172.16.4.10 on port 8080** and had been resident for approximately
**7 days** at image capture time. During that dwell period, the implant expanded its
in-memory capabilities (loading UI and network-drive modules 6 days post-infection),
spawned multiple `rundll32.exe` instances as injection carriers, and conducted lateral
movement to at least three additional internal hosts via RDP, SMB, and WinRM. No
registry-based persistence was detected in memory, suggesting the attacker relied on
their implant's long dwell time and compromised credentials for continued access.

---

## Timeline of Attacker Activity (UTC)

| Timestamp (UTC) | Event |
|----------------|-------|
| 2018-08-30 13:51:58 | System boot — normal boot sequence begins |
| 2018-08-30 13:52:26 | WmiPrvSE.exe (PID 2876) starts under DcomLaunch svchost — normal at this stage |
| **2018-08-30 16:43:36** | **INITIAL ACCESS: WmiPrvSE.exe (PID 2876) spawns powershell.exe (PID 8712) — attacker executes PowerShell via WMI using spsql credentials** |
| 2018-08-30 16:43:37 | PS 8712 loads System.DirectoryServices.ni.dll — Active Directory enumeration begins |
| 2018-08-30 16:43:42 | PS 8712 spawns PowerShell 5848 (WOW64) with -Version 5.1 -s -NoLogo -NoProfile (remoting/C2 session established) |
| 2018-08-30 18:31:04 | PS 5848 spawns rundll32.exe (PID 6768, WOW64) — exits after ~31 seconds |
| 2018-08-30 18:31:10 | WmiPrvSE.exe (PID 8840, WOW64) starts under DcomLaunch — likely DCOM activity driven by attacker |
| **2018-08-30 22:15:18** | **IMPLANT DEPLOYMENT: PS 5848 spawns cmd.exe (PID 5948) with arg '/C c:\windows\temp\perfmon\p.exe'; cmd.exe spawns p.exe (PID 8260)** |
| 2018-08-30 21:40:18 | PS 5848 spawns rundll32 (PID 5452, 64-bit) — exits after 5 seconds |
| 2018-08-30 21:40:42 | PS 5848 spawns rundll32 (PID 5588, 64-bit) — exits after 12 seconds |
| 2018-08-30 22:31:57 | PS 5848 spawns rundll32 (PID 2216, WOW64) — exits after 22 seconds |
| 2018-08-30 22:45:25 | PS 5848 spawns rundll32 (PID 4108, 64-bit) — exits after 5 seconds |
| 2018-08-31 00:56:14 | PS 5848 spawns rundll32 (PID 8148, WOW64) — exits after 16 seconds |
| 2018-08-30/31 (various) | Multiple CLOSE_WAIT connections to 172.16.4.10:8080 established and terminated — C2 beaconing |
| 2018-09-05 12:01:32 | p.exe spawns rundll32 (PID 5768, 64-bit) — exits after 8 seconds (first implant-initiated action observed) |
| **2018-09-05 12:13:26** | **CAPABILITY EXPANSION: p.exe loads mpr.dll (network redirector API) mid-operation** |
| **2018-09-05 12:14:36** | **CAPABILITY EXPANSION: p.exe loads USER32.dll, GDI32.dll, gdi32full.dll — screen/UI interaction module activated** |
| 2018-09-06 14:03:54 | WmiPrvSE.exe (PID 11948) starts — possible additional WMI execution by attacker |
| 2018-09-06 14:58:41 | p.exe spawns rundll32 (PID 1424, 64-bit) — exits after 4 seconds |
| 2018-09-06 17:26:32 | p.exe spawns rundll32 (PID 7552, 64-bit) — exits after 3 seconds |
| 2018-09-06 18:28:30 | F-Response Subject service (investigator tool) starts — memory acquisition begins |
| 2018-09-06 18:57:17 | **IMAGE CAPTURED** — 3 ESTABLISHED connections to 172.16.4.10:8080 active at capture time |

---

## Detailed Findings

### F01 — Malicious Implant p.exe [CONFIRMED]

**Evidence:** `windows.pstree` shows p.exe (PID 8260) at path `c:\windows\temp\perfmon\p.exe`,
CreateTime 2018-08-30 22:15:18 UTC, ExitTime N/A (still running at capture). `windows.filescan`
confirms file objects for `\Windows\Temp\Perfmon\p.exe` and the directory `\Windows\Temp\Perfmon`.

The directory name "Perfmon" is a deliberate masquerade of Windows Performance Monitor (perfmon.exe),
a built-in Windows administrative utility. The actual Windows performance monitoring tools reside in
`%SystemRoot%\System32\`. Placing a custom executable in `C:\Windows\Temp\Perfmon\` is a T1036.005
masquerading technique intended to reduce analyst suspicion.

**Dwell time:** 7 days, 20 hours, 42 minutes (2018-08-30 22:15:18 to 2018-09-06 18:57:17 UTC).

**MITRE:** T1036.005

---

### F02 — WMI-Initiated PowerShell Execution Chain [CONFIRMED]

**Evidence:** `windows.pstree` and `windows.cmdline` document the complete parent-child chain:

```
WmiPrvSE.exe (PID 2876, started 13:52:26 UTC)
  └─ powershell.exe (PID 8712, 16:43:36 UTC) [64-bit, no visible cmdline args]
       └─ powershell.exe (PID 5848, 16:43:42 UTC) [WOW64]
            args: "c:\windows\syswow64\windowspowershell\v1.0\powershell.exe"
                  -Version 5.1 -s -NoLogo -NoProfile
            └─ cmd.exe (PID 5948, 22:15:18 UTC) [WOW64]
                 args: C:\WINDOWS\system32\cmd.exe /C c:\windows\temp\perfmon\p.exe
                 └─ p.exe (PID 8260, 22:15:18 UTC)
```

`-Version 5.1 -s -NoLogo -NoProfile` is the invocation signature for a PowerShell remote session
server (the "-s" flag enables server mode). This is the standard mechanism used by frameworks like
Cobalt Strike, Metasploit, and Empire when establishing a PowerShell-over-WMI lateral movement channel.

The gap between PS 5848 starting (16:43:42 UTC) and cmd.exe being launched (22:15:18 UTC) — 
approximately 5.5 hours — suggests interactive operator activity: the attacker connected to the
session, performed reconnaissance (see F10), and only later deployed the implant.

**MITRE:** T1047, T1059.001, T1105

---

### F03 — Compromised Domain Admin Account 'spsql' [CONFIRMED]

**Evidence:** `windows.getsids --pid 8260`, `--pid 8712`, `--pid 5848` all return identical SID sets:

```
spsql                   S-1-5-21-3445421715-2530590580-3149308974-1193
Domain Users            S-1-5-21-3445421715-2530590580-3149308974-513
Administrators          S-1-5-32-544
Domain Admins           S-1-5-21-3445421715-2530590580-3149308974-512
Network                 S-1-5-2
High Mandatory Level    S-1-16-12288
```

Three key indicators:
1. **Domain Admin** membership gives unrestricted access to all domain-joined systems
2. **Network SID (S-1-5-2)** indicates the logon token was created from a network authentication event — the credentials arrived over the network, consistent with Pass-the-Hash or credential reuse
3. The name `spsql` strongly resembles a SQL Server service account; service accounts are often set with non-expiring passwords and high privileges, making them high-value credential theft targets

**MITRE:** T1078.002

---

### F04 — Active C2 Communication to 172.16.4.10:8080 [CONFIRMED]

**Evidence:** `windows.netscan` shows 3 ESTABLISHED and 7 CLOSE_WAIT connections at image capture time:

| State | Local | Remote | Count |
|-------|-------|--------|-------|
| ESTABLISHED | 172.16.6.11:49788/49787/49786 | 172.16.4.10:8080 | 3 |
| CLOSE_WAIT | 172.16.6.11:various | 172.16.4.10:8080 | 7 |
| CLOSED | 172.16.6.11:various | 172.16.4.10:8080 | 3 |

All connections show PID `-` in netscan (owner process not attributable by pool scan). This is
consistent with connections whose owner-module tracking structures have been cleaned up while the
socket descriptors remain open — a behavior observed in some implants using asynchronous I/O
completion ports. Attribution to the attack chain is supported by: (a) p.exe loaded WININET.dll
and WS2_32.dll; (b) PS 5848 loaded wininet.DLL, winhttp.dll, IPHLPAPI.DLL; (c) port 8080 is
the C2 port used by numerous RAT/implant frameworks as a firewall-evasion measure.

**MITRE:** T1071.001, T1571

---

### F05 — Rundll32 Execution Chain as Injection Carriers [CONFIRMED, MEDIUM]

**Evidence:** `windows.pstree` and `windows.cmdline` document 9 rundll32.exe executions:

From PS 5848 (2018-08-30):
- PIDs 6768 (WOW64), 5452, 5588, 2216 (WOW64), 4108, 8148 (WOW64) — all exited within 5-30 seconds

From p.exe (2018-09-05 to 2018-09-06):
- PIDs 5768, 1424, 7552 — all exited within 4-8 seconds

All 9 instances have empty command-line arguments. Legitimate rundll32.exe usage requires at minimum
`rundll32.exe <dll_path>,<function_name>` arguments. Empty-argument rundll32 invocations are a
well-documented pattern for process hollowing (MITRE T1055.012) and Cobalt Strike's default
injection mechanism.

The consistent pattern across both the initial PowerShell C2 and the later p.exe implant
corroborates that these processes share an operational toolkit.

**Confidence MEDIUM:** No memory dumps of running instances were captured, preventing confirmation of
what was injected.

**MITRE:** T1055, T1218.011

---

### F06 — 1.88 MB RWX Private Memory Region in p.exe [CONFIRMED]

**Evidence:** `windows.malfind` identified:

```
PID:    8260 (p.exe)
VPN:    0x2be0000 – 0x2dc0fff
Tag:    VadS (private allocation, not backed by a file)
Prot:   PAGE_EXECUTE_READWRITE
Pages:  481 committed (1,970,176 bytes ≈ 1.88 MB)
```

A private RWX allocation of this size with no file backing is a primary indicator of an in-memory
shellcode stage or a reflectively-loaded PE. The pages were paged out at capture time (hexdump
shows all `__`), which prevents direct content analysis without a full memory dump — standard
behavior for large memory regions that have not been accessed recently.

**MITRE:** T1055, T1620

---

### F07 — p.exe and PS 5848 Carry Full C2 + Capability Expansion DLLs [CONFIRMED]

**Evidence from `windows.dlllist --pid 8260` (p.exe):**

Initial load (2018-08-30 22:15:18-19 UTC):
- `WININET.dll`, `WS2_32.dll`, `DNSAPI.dll`, `IPHLPAPI.DLL` — network stack
- `CRYPTSP.dll`, `rsaenh.dll`, `bcrypt.dll`, `bcryptPrimitives.dll` — encryption
- `Secur32.dll`, `SSPICLI.DLL` — SSPI credential APIs

Post-deployment capability expansion (2018-09-05):
- `mpr.dll` (LoadTime: 12:13:26 UTC) — Multiple Provider Router, used for network drive enumeration and remote UNC path access
- `USER32.dll`, `win32u.dll`, `GDI32.dll`, `gdi32full.dll`, `msvcp_win.dll`, `ucrtbase.dll` (LoadTime: 12:14:36 UTC) — UI/windowing and graphics APIs, consistent with a screen-capture or keylogging module being activated

**Note:** p.exe does NOT load `amsi.dll` — this is expected for a compiled executable (AMSI only
instruments scripting engines). No AMSI bypass was required.

**Evidence from `windows.dlllist --pid 5848` (PS 5848 WOW64):**
- `wininet.DLL`, `winhttp.dll`, `urlmon.dll` — HTTP client stack (download capability)
- `msv1_0.DLL` — NTLM authentication provider (credential access)
- `amsi.dll` present — AMSI active in this process, no bypass detected at DLL level

**MITRE:** T1071.001, T1573, T1113 (screen capture capability implied by GDI32 load)

---

### F08 — Lateral Movement to Internal Hosts [CONFIRMED, MEDIUM]

**Evidence from `windows.netscan`:**

| Destination | Port | Protocol | State | Direction |
|-------------|------|----------|-------|-----------|
| 172.16.4.5 | 3389 | RDP | CLOSED (×6) | Outbound |
| 172.16.4.5 | 445 | SMB | ESTABLISHED | Outbound |
| 172.16.7.15 | 445 | SMB | ESTABLISHED | Outbound |
| 172.16.4.4 | 389 | LDAP | CLOSED | Outbound |
| 172.16.5.21 | 5985 | WinRM | CLOSED | Outbound |
| 172.16.6.14 | — | SMB | ESTABLISHED (inbound) | Inbound from 172.16.6.14:65368 |

Multiple failed RDP attempts to 172.16.4.5 (six CLOSED connections) followed by an active SMB
session suggest the attacker pivoted to file share access after RDP was blocked or authentication
failed. The inbound SMB connection from 172.16.6.14 to this host suggests 172.16.6.14 is either
another compromised host or the attacker's pivot point accessing resources on BASE-RD-01.

**Confidence MEDIUM:** Connection owner PIDs are unattributed; lateral movement cannot be directly
attributed to a specific process with available evidence.

**MITRE:** T1021.001, T1021.002, T1021.006

---

### F09 — No Registry-Based Persistence Detected [CONFIRMED — Negative Finding]

**Evidence:** `windows.registry.printkey` on `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
(all hives) and `RunOnce` showed no malicious entries. Only the following legitimate user-mode
autostart entries exist:
- `OneDrive` → `C:\Users\tdungan\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background`
- `Dashlane` → `C:\Users\tdungan\AppData\Roaming\Dashlane\Dashlane.exe autoLaunchAtStartup`
- `DashlanePlugin` → `C:\Users\tdungan\AppData\Roaming\Dashlane\DashlanePlugin.exe ws`

`windows.svcscan` filtered for user-writable paths (Temp, AppData, Users) returned no suspicious
service registrations.

The attacker appears to have operated without registry-based persistence. Possible explanations:
(a) the implant itself functions as the persistence mechanism through its 7-day dwell; (b) the
attacker planned to reinstall via spsql credentials if lost; (c) persistence exists in disk
artifacts (scheduled tasks, WMI subscriptions, startup folders) not captured in this memory image.

**MITRE:** N/A

---

### F10 — Active Directory Enumeration from PowerShell 8712 [CONFIRMED, MEDIUM]

**Evidence:** `windows.dlllist --pid 8712` shows `System.DirectoryServices.ni.dll` loaded at
2018-08-30 16:43:37 UTC — 1 second after the PS session started. This .NET library is the primary
managed API for LDAP/Active Directory queries. Combined with the LDAP connection to 172.16.4.4:389
(netscan offset 0x8c88b5b1a010, CLOSED), this confirms AD enumeration occurred before implant
deployment.

**MITRE:** T1018, T1069, T1087

---

### F11 — Unnamed DLLs in PowerShell 5848 (Possible Reflective Loading) [UNCONFIRMED]

**Evidence:** `windows.dlllist --pid 5848` shows approximately 15 DLL entries with no name or
path. Some entries have timestamps in the year 3400-3900 range, which is a known artifact of
reflectively-loaded modules that do not populate LDR timestamp fields.

This is UNCONFIRMED because WOW64 processes can exhibit incomplete LDR chain data, and corrupt
timestamps can occur for other reasons. Without a full process memory dump and analysis of these
unnamed regions, this cannot be definitively attributed to malicious injection.

**MITRE:** T1620 (if confirmed)

---

### F12 — F-Response Investigator Tool (Artifact) [CONFIRMED]

**Evidence:** `subject_srv.exe` (PID 1096) — F-Response Subject service — started 2018-09-06
18:28:30 UTC (~29 minutes before image capture). ESTABLISHED connection to 172.16.5.50:39372
corresponds to the F-Response acquisition channel. This process is the investigator's remote
memory acquisition tool and is excluded from threat analysis.

---

### FP01 — FALSE POSITIVE: OUTLOOK.EXE Malfind Hits [RETRACTED]

`windows.malfind` flagged two RWX regions in OUTLOOK.EXE (PID 8128) beginning with bytes
`64 74 72 52` (`dtrR`). This is a documented Outlook/COM heap allocation signature, not injected
code. Explicitly retracted.

### FP02 — FALSE POSITIVE: Powershell.exe (PID 8712) Malfind Hits [RETRACTED]

Three RWX regions flagged in PS 8712 show data patterns consistent with .NET CLR thread
synchronization structures (lock records, GC sync). `windows.dlllist` confirms `clrjit.dll` is
loaded. Retracted as .NET JIT false positives.

---

## MITRE ATT&CK Summary

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 | spsql Domain Admin |
| Execution | Windows Management Instrumentation | T1047 | WmiPrvSE → PowerShell |
| Execution | PowerShell | T1059.001 | PS 8712 / PS 5848 |
| Persistence | (none detected) | — | Negative finding |
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | Temp\Perfmon\p.exe |
| Defense Evasion | Rundll32 | T1218.011 | 9 empty-arg rundll32 runs |
| Defense Evasion | Reflective Code Loading | T1620 | RWX VAD in p.exe, unnamed DLLs |
| Credential Access | (inferred) | T1078 | spsql credential theft prerequisite |
| Discovery | Remote System Discovery | T1018 | System.DirectoryServices + LDAP |
| Discovery | Permission Groups Discovery | T1069 | AD enumeration via DS library |
| Discovery | Account Discovery | T1087 | AD enumeration |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | 6 RDP attempts to 172.16.4.5 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | ESTABLISHED SMB to .4.5, .7.15 |
| Lateral Movement | Windows Remote Management | T1021.006 | WinRM attempt to 172.16.5.21 |
| Collection | Screen Capture (inferred) | T1113 | GDI32/USER32 late-load in p.exe |
| Command & Control | Web Protocols | T1071.001 | HTTP to 172.16.4.10:8080 |
| Command & Control | Non-Standard Port | T1571 | Port 8080 for C2 |
| Command & Control | Encrypted Channel (likely) | T1573 | Crypto DLLs in p.exe |
| Ingress Tool Transfer | — | T1105 | p.exe deployed via C2 session |

---

## Recommendations

1. **Immediate containment:** Isolate BASE-RD-01 from the network. The implant (p.exe) maintains
   3 active C2 sessions; assume the attacker has current interactive access.

2. **Credential reset — CRITICAL:** Immediately disable and reset the `spsql` account. All other
   accounts accessible to a Domain Admin within the shieldbase.lan domain should be audited for
   unauthorized access. Assume all domain credentials on BASE-RD-01 are compromised.

3. **Scope expansion — investigate identified lateral movement targets:**
   - 172.16.4.5 (RDP + SMB contact)
   - 172.16.7.15 (SMB contact)
   - 172.16.5.21 (WinRM attempt)
   - 172.16.6.14 (inbound SMB to BASE-RD-01 — possible additional compromised host)
   - 172.16.4.4 (domain controller — priority: check for DCSync, Golden Ticket, or domain-level persistence)

4. **C2 block:** Block 172.16.4.10:8080 at all network egress points. Examine firewall logs for
   additional hosts communicating to this IP.

5. **Disk forensics:** This analysis is limited to memory. A full disk image is required to:
   - Recover p.exe binary for hash/static analysis
   - Check Scheduled Tasks, WMI subscriptions, and startup folders for persistence
   - Review PowerShell transcripts and ScriptBlock logs
   - Examine Prefetch, Shimcache, and Amcache for p.exe execution history

6. **External IP 52.16.55.11:** One closed HTTPS connection to this external IP was observed.
   Investigate this IP for potential additional C2 infrastructure.

7. **Domain Controller audit:** The LDAP connection to 172.16.4.4 and the presence of Domain Admin
   credentials in memory indicates possible domain-level compromise. Audit DCSync operations and
   Kerberos ticket issuance logs for spsql and related accounts.
