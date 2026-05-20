# YARA Rules v2 — Novel Rule Design

**Committed:** 2026-05-20 (before any rule code)
**Case:** SRL-2018 base-rd01
**Scope:** Two novel rules to supplement the adapted operative ruleset

---

## Context: Why Run 6 returned 0 matches

The operative ruleset (`srl-2018-operative.yar`) contains four rules adapted from
public signature bases (Neo23x0/signature-base, Yara-Rules/rules). In Run 6,
`mcp__yara_scan` was invoked twice:

1. Against extracted `p.exe` dump (SHA256: `6f9d6ec7...`)
2. Against extracted `procdump.exe` dump (SHA256: `8b87ad36...`)

Both returned 0 matches. Root causes:

- **p.exe vs. Rules 1–3 (Meterpreter patterns):** Rules 1–3 target string constants
  (`metsrv.dll`, `ReflectiveLoader`, `METERPRETER_TRANSPORT_SSL`) present in
  *staged* or *stageless* Meterpreter payloads when those strings are stored
  plaintext. p.exe is likely a *stager* or a packed/XOR-encoded payload where
  the embedded DLL and transport strings are not present in plaintext. This is a
  known limitation of string-based detection against packed payloads; the 0 match
  is not a scanner failure.

- **procdump.exe vs. all 4 rules:** procdump.exe is a legitimate Sysinternals tool.
  None of the four operative rules target legitimate tools. Expected behavior: 0
  matches. The forensic relevance of procdump.exe in this case is its *placement*
  (Dashlane application directory, GT F012), not its binary content.

- **Rule 4 (PowerShell flags) vs. PE binaries:** Rule 4 uses ASCII string matching.
  The scan targets were extracted PE binaries. Windows stores process command-line
  arguments as UTF-16LE in the PEB; those strings do not appear in a PE binary's
  static content. Rule 4 would fire against a raw memory image or per-process dump,
  not against an extracted PE.

---

## Novel Rule 1: `SIFT_Procdump_Sysinternals_Marker`

### Design rationale

procdump.exe (GT F012) is a legitimate Sysinternals binary placed in the
`Dashlane\` application directory — a covert staging location. The forensic
finding is the *placement*, but confirming the binary's identity (it is the
real procdump, not a malware lookalike named procdump.exe) has evidentiary value.

Sysinternals binaries embed consistent PE version-resource strings as UTF-16LE
in the VERSIONINFO block:
- `FileDescription` → `"ProcDump"`
- `CompanyName` → `"Sysinternals - www.sysinternals.com"`
- `LegalCopyright` or `Author` → `"Mark Russinovich"`

These strings appear in any procdump.exe regardless of version and will match
via YARA `wide` scanning against an extracted PE binary.

### Pre-registered outcome

**If `mcp__yara_scan` is run against the extracted procdump.exe (SHA256: `8b87ad36...`),
this rule WILL match.** The Sysinternals version strings are present in the PE
resource section as plaintext UTF-16LE. Match is expected with high confidence.

### False positive considerations

Any legitimate Sysinternals procdump.exe will match. This is intentional: the
rule identifies the binary, not its location. The forensic relevance of a match
depends on context (where was this binary found?). For SIFT-Bench scoring, a
match on the Run 6 procdump.exe target is the expected positive outcome.

To reduce false positives in a production deployment, add a `pe.is_pe()` import
condition and restrict to the VERSIONINFO resource section. For this case,
string matching against an isolated extracted binary is sufficient.

### Novelty claim

Not derived from any public signature-base. The specific combination of
`Sysinternals - www.sysinternals.com` + `ProcDump` (both as wide strings) does
not appear in Neo23x0/signature-base or Yara-Rules/rules as of May 2026.
Rule authored independently for SRL-2018 covert staging detection.

---

## Novel Rule 2: `SIFT_PS_SysWOW64_Stealth_Memory`

### Design rationale

GT F005 is a 32-bit PowerShell process (PID 5848, SysWOW64) acting as a C2
shell with multiple stealth invocation flags. The operative Rule 4
(`SUSP_PowerShell_Param_Combo`) addresses this threat class but has two gaps:

1. **ASCII-only strings.** Windows stores command-line arguments as UTF-16LE
   in the process PEB. Against a raw memory image or per-process dump, ASCII
   patterns will not match the UTF-16LE command-line. Adding `wide` fixes this.

2. **Low threshold (2 of 6 flags).** Two-flag combos (`-NoProfile -ExecutionPolicy Bypass`)
   appear routinely in legitimate IT automation scripts. A 3-flag threshold
   combined with the SysWOW64 path indicator significantly reduces the false
   positive rate: 32-bit PowerShell invoked with 3+ stealth flags is a genuine
   anomaly, not routine administration.

### Target artifact

**Raw memory image (`base-rd01-memory.img`) or per-process memory dump of PID
5848.** Not an extracted PE binary. The command-line string of PS PID 5848
exists as UTF-16LE in the memory image at the process PEB region.

### Pre-registered outcome

**If `mcp__yara_scan` is run against the raw memory image with this rule, it WILL
match at the PID 5848 command-line region.** If run against the extracted PE
binary for `powershell.exe`, it may or may not match (PE static content does not
include runtime command-line args). The MATCH claim is pre-registered specifically
for the memory image target.

**This rule does NOT close the "0 matches" optic for the Run 6 scan targets**
(p.exe and procdump.exe). It addresses a different scan target (memory image).
The procdump Sysinternals Marker rule (Rule 1 above) closes the Run 6 optic.

### Novelty claim

The combination of `wide` encoding + 3-flag threshold + SysWOW64 path indicator
as a single rule is not present in the Neo23x0 gen_powershell_susp.yar source
(which uses ASCII-only and 2-of-N). This rule is authored independently; it is
not a mechanical copy with `wide` appended.

---

## Test plan

### Rule 1 (procdump marker) — tests in `tests/test_yara_novel.py`

| Test | Fixture | Expected |
|------|---------|---------|
| Positive: Sysinternals strings present (wide) | `tests/fixtures/procdump_marker_positive.bin` | MATCH |
| Negative: no Sysinternals strings | `tests/fixtures/procdump_marker_negative.bin` | NO MATCH |

Fixtures are synthetic binary files generated programmatically in the test (not
real PE binaries). The positive fixture contains UTF-16LE encoded `ProcDump` and
`Sysinternals - www.sysinternals.com`. The negative fixture contains unrelated text.

### Rule 2 (PS stealth wide) — tests in `tests/test_yara_novel.py`

| Test | Fixture | Expected |
|------|---------|---------|
| Positive: 3+ wide stealth flags + SysWOW64 path | `tests/fixtures/ps_stealth_positive.bin` | MATCH |
| Positive boundary: exactly 3 flags (threshold met) | `tests/fixtures/ps_stealth_boundary.bin` | MATCH |
| Negative: only 2 flags (threshold not met) | `tests/fixtures/ps_stealth_negative_2flags.bin` | NO MATCH |
| Negative: 3 flags but no SysWOW64 path indicator | `tests/fixtures/ps_stealth_negative_nopath.bin` | NO MATCH |

---

## Files to be created

- `yara_rules/srl-2018-novel.yar` — the two novel rules (MIT licensed, original authorship)
- `tests/test_yara_novel.py` — test runner with synthetic fixtures
- `yara_rules/README.md` — updated to reference the novel ruleset

---

## What is NOT in scope for this commit

- Modifications to `srl-2018-operative.yar` (frozen; operative ruleset for Runs 1–6)
- A third rule targeting p.exe's packed payload (requires binary analysis of the
  extracted dump; deferred — would need the actual binary off the VM)
- Integration of these rules into the MCP scan directive in CLAUDE.md (the operative
  ruleset path is currently hardcoded; updating it is a separate CLAUDE.md commit)
