# SIFT-Bench YARA Rules

## `srl-2018-operative.yar` — operative ruleset for SRL-2018

One community detection rule (GPLv2, aggregated — see licensing note below),
scoped to an artifact type confirmed in the SRL-2018 memory image. It is
excerpted/adapted from the source file listed below; see the source for the
authoritative text and full context. The project's original detection
contribution is in `srl-2018-novel.yar`.

This ruleset is the input to `mcp__yara_scan` calls during Phase 1 enrichment
of Run 4. It is distinct from `tests/yara_rules/test_marker.yar`, which is a
test fixture only.

---

### Rule provenance

#### `RAT_Meterpreter_Reverse_Tcp` — the sole bundled community rule

| Field | Value |
|-------|-------|
| Source file | `malware/RAT_Meterpreter_Reverse_Tcp.yar` |
| Repository | [Yara-Rules/rules](https://github.com/Yara-Rules/rules) |
| License | GPLv2 (aggregated, not relicensed) |
| Authors | Yara-Rules Project |
| Detection | Meterpreter reverse-TCP transport configuration constants (`METERPRETER_TRANSPORT_SSL`, `METERPRETER_UA`) |
| Scope | p.exe C2 implant — transport-layer strings |

Fires on transport-layer configuration constants embedded in a configured
Meterpreter payload. It sits alongside the MIT-licensed code as **mere
aggregation** (GPLv2 §2): it is data input to the scanner, not a derivative
work, so it does not relicense the repository.

---

### Licensing summary

| Source | License | Status |
|--------|---------|--------|
| Yara-Rules/rules | GPLv2 | Aggregated (data input; mere aggregation, not relicensed) |

Three CC BY-NC 4.0 community rules were removed to keep the bundled ruleset
fully permissive; they were inert (0 matches) in all committed runs, so
detection results are unaffected, and the novel rules are the detection
contribution. Removed on 2026-06-13: `HKTL_Meterpreter_inMemory`,
`HKTL_CobaltStrike_Beacon_Strings`, `SUSP_PowerShell_Param_Combo` (all
Neo23x0/signature-base, CC BY-NC 4.0). The one remaining community rule (GPLv2)
is aggregated, not relicensed. SIFT-Bench's own code and the novel rules in
`srl-2018-novel.yar` are MIT-licensed.

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
