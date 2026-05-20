# SIFT-Bench YARA Rules

## `srl-2018-operative.yar` — operative ruleset for SRL-2018

Four rules from two established sources, scoped to artifact types confirmed in
the SRL-2018 memory image. These are excerpted/adapted from the source files
listed below; see each source for the authoritative text and full context.

This ruleset is the input to `mcp__yara_scan` calls during Phase 1 enrichment
of Run 4. It is distinct from `tests/yara_rules/test_marker.yar`, which is a
test fixture only.

---

### Rule provenance

#### 1. `HKTL_Meterpreter_inMemory`

| Field | Value |
|-------|-------|
| Source file | `yara/gen_metasploit_payloads.yar` |
| Repository | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) |
| License | CC BY-NC 4.0 |
| Authors | netbiosX, Florian Roth (Nextron Systems) |
| Detection | Meterpreter in-memory via DLL naming patterns (`metsrv.dll`, `metsrv.x64.dll`, `ReflectiveLoader`) |
| Scope | p.exe implant identification |

**Condition note:** `WS2_32.dll` alone is not specific (any network-capable binary
matches), but in combination with `metsrv.*` or `ReflectiveLoader` it is a strong
signal. Condition `2 of them` reflects the original rule's intent.

---

#### 2. `HKTL_CobaltStrike_Beacon_Strings`

| Field | Value |
|-------|-------|
| Source file | `yara/apt_cobaltstrike.yar` |
| Repository | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) |
| License | CC BY-NC 4.0 |
| Credit | Elastic (rule authored by Elastic Security team) |
| Detection | Cobalt Strike Beacon DLL diagnostic format strings |
| Scope | p.exe alternative C2 identification |

**Why included:** p.exe has a network-capable DLL profile (WININET, crypto stack)
consistent with either Meterpreter or a Cobalt Strike beacon. Including both
detection families covers the uncertainty about which specific C2 framework was
used.

---

#### 3. `RAT_Meterpreter_Reverse_Tcp`

| Field | Value |
|-------|-------|
| Source file | `malware/RAT_Meterpreter_Reverse_Tcp.yar` |
| Repository | [Yara-Rules/rules](https://github.com/Yara-Rules/rules) |
| License | GPLv2 |
| Authors | Yara-Rules Project |
| Detection | Meterpreter reverse-TCP transport configuration constants (`METERPRETER_TRANSPORT_SSL`, `METERPRETER_UA`) |
| Scope | p.exe C2 implant — transport-layer strings |

**Relationship to rule 1:** rule 1 fires on the staging DLL naming patterns;
rule 3 fires on the transport-layer configuration constants embedded in the
configured payload. Complementary, not redundant.

---

#### 4. `SUSP_PowerShell_Param_Combo`

| Field | Value |
|-------|-------|
| Source file | `yara/gen_powershell_susp.yar` |
| Repository | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) |
| License | CC BY-NC 4.0 |
| Author | Florian Roth (Nextron Systems) |
| Detection | Suspicious PowerShell invocation parameter combinations |
| Scope | Stealth C2 shell — PS 5848 used `-NoLogo -NoProfile -s` flags |

**Adaptation note:** the exact rule name in the source file may differ; the string
set (`-nop`, `-noni`, `-enc`, `-w hidden`, `-EncodedCommand`, `-WindowStyle Hidden`)
and `2 of them` condition are consistent with known versions of this rule.
This rule fires on file content (extracted scripts, memory regions) containing
PS invocation strings, not on a live process command line.

---

### Licensing summary

| Source | License | Restriction |
|--------|---------|-------------|
| Neo23x0/signature-base | CC BY-NC 4.0 | Non-commercial use only |
| Yara-Rules/rules | GPLv2 | Copyleft |

SIFT-Bench is an MIT-licensed project. Rules sourced from these repositories
are used here for a non-commercial research and competition submission. The
rules themselves remain under their original licenses; they are not
relicensed by inclusion in this repo.

---

## `srl-2018-novel.yar` — novel rules (original authorship)

Two rules written independently for the SRL-2018 case, not derived from any
public signature base. See `design/yara-rules-v2.md` for full rationale,
pre-registered match outcomes, and test plan. Tests in `tests/test_yara_novel.py`
(13 cases, all passing; uses `yara-python` module).

### Rule 1: `SIFT_Procdump_Sysinternals_Marker`

Identifies a Sysinternals ProcDump binary via PE version-resource strings stored
as UTF-16LE (`ProcDump`, `Sysinternals`, `Mark Russinovich`; condition: 2 of 3).

- **Target artifact:** extracted PE binary or memory region containing procdump image
- **GT finding:** F012 (procdump.exe in Dashlane staging directory)
- **Pre-registered outcome:** MATCH expected against Run 6 extracted procdump.exe (SHA256: `8b87ad36...`)
- **License:** MIT (original authorship)

### Rule 2: `SIFT_PS_SysWOW64_Stealth_Memory`

Detects 32-bit PowerShell with 3+ stealth invocation flags in a memory image.
Addresses two gaps in operative Rule 4: (a) ASCII-only strings miss UTF-16LE
command-line args in memory; (b) 2-flag threshold is too broad for live automation.
This rule requires `SysWOW64\WindowsPowerShell` path indicator + 3 of 7 stealth
flags, all as `wide` (UTF-16LE) strings.

- **Target artifact:** raw memory image or per-process dump — NOT an extracted PE binary
- **GT finding:** F005 (PowerShell PID 5848, 32-bit, C2 shell with stealth flags)
- **Pre-registered outcome:** MATCH expected against `base-rd01-memory.img` at PID 5848 PEB region; NOT expected to match extracted PE binaries
- **License:** MIT (original authorship)

---

### What is NOT here

- **tests/yara_rules/test_marker.yar**: a test fixture only; not used in production scanning.
