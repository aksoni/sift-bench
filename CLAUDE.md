# CLAUDE.md

This file provides guidance to Claude Code when working on DFIR cases using the SANS SIFT Workstation.

## DFIR Orchestrator — SANS SIFT Workstation (SIFT-Bench Extended)

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |
| **Extension** | SIFT-Bench self-correction + threat intel enrichment |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run every workflow fully autonomously start-to-finish. No check-ins, no confirmations, no "shall I proceed?". Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.

---

## Forensic Constraints

- **No hallucinations** — Never guess, assume, or fabricate forensic artifacts, file contents, or system states.
- **Deterministic execution** — Use court-vetted CLI tools to generate facts; ground all conclusions in raw tool output.
- **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — Write all scripts, CSVs, JSON, and reports to `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or evidence directories.
- **Timestamps** — Always output in UTC.
- **Verification** — Verify tool success after every run. On failure: read stderr → hypothesize → correct → retry.

---

## Installed Tool Paths

| Tool | Invocation | Notes |
|------|-----------|-------|
| **Volatility 3** | `vol` | Installed via pipx; available on PATH |
| **YARA** | `/usr/local/bin/yara` (v4.1.0) | |
| **Sleuth Kit** | `fls`, `icat`, `ils`, `blkls`, `mactime`, `tsk_recover` | System PATH |
| **EWF tools** | `ewfmount`, `ewfinfo`, `ewfverify` | System PATH |
| **Plaso** | `log2timeline.py`, `psort.py`, `pinfo.py` | GIFT PPA |
| **bulk_extractor** | `bulk_extractor` (v2.0.3) | Defaults to 4 threads |

---

## Tool Routing

> Consult the relevant skill file before executing a forensic utility.

| Domain | Skill File |
|--------|-----------|
| Case scope & metadata | `@./CLAUDE.md` (this file) |
| Timeline generation (Plaso) | `@~/.claude/skills/plaso-timeline/SKILL.md` |
| File system & carving (Sleuth Kit) | `@~/.claude/skills/sleuthkit/SKILL.md` |
| Memory forensics (Volatility 3) | `@~/.claude/skills/memory-analysis/SKILL.md` |
| Windows artifacts (EZ Tools / Event Logs / Registry) | `@~/.claude/skills/windows-artifacts/SKILL.md` |
| Threat hunting & IOC sweeps (YARA) | `@~/.claude/skills/yara-hunting/SKILL.md` |
| Self-correction protocol | `@~/.claude/skills/self-correction/SKILL.md` |

---

## Analysis Workflow

Execute these phases in order for every case:

### Phase 1: INVESTIGATE + ENRICH

Run the full memory analysis methodology (see memory-analysis skill file):

1. **Process enumeration** — `windows.psscan` (pool scan for hidden/exited processes)
2. **Process tree** — `windows.pstree` (parent-child relationships; identify anomalies)
3. **Command lines** — `windows.cmdline` (attacker commands, LOLBin usage)
4. **Network connections** — `windows.netscan` (C2, lateral movement, exfiltration indicators)
5. **Code injection** — `windows.malfind` (RWX regions, injected code, false positives)
6. **File scan** — `windows.filescan` (suspicious file paths, staging directories, prefetch)
7. **Credential context** — `windows.getsids` (account privileges for suspicious processes)
8. **DLL analysis** — `windows.dlllist` on PIDs identified as attacker-controlled
   (the C2 PowerShell shells, p.exe, and any rundll32 instances that did not exit).
   Report: full DLL inventory for p.exe (network stack and crypto libraries indicate
   implant capability), load timestamps showing post-execution DLL loading (indicates
   implant remained active and gained capabilities over time), and presence of amsi.dll
   or unnamed DLLs (potential reflective loading indicators).

9. **Persistence check** — Run `windows.registry.printkey` on at minimum:
   - SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   - SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
   Also run `windows.svcscan` and grep for services in user-writable paths or with
   suspicious names. If no persistence mechanisms are found, explicitly state this as
   a negative finding in the report ("No registry-based persistence detected; svcscan
   revealed no malicious services").

**Enrichment (inline):** Whenever you encounter a suspicious file during investigation:
- Extract the binary first using `vol ... windows.dumpfiles` (or `windows.dumpfiles --physoffset` for pool-scan hits)
- **Hash using `mcp__hash_file` only.** Do not use `sha256sum`, `certutil`, `Get-FileHash`, `hashlib`, or any other inline hash method — they produce unattributed output that cannot be verified. Record the `sha256` field from the `mcp__hash_file` response in `evidence.file_hash_sha256`.
- **Scan using `mcp__yara_scan` only**, with `rules_path` pointing to `yara_rules/srl-2018-operative.yar`. Do not use `/usr/local/bin/yara`, `yara.compile()`, or any other direct YARA invocation — they bypass the registered tool and produce unattributed output. Include any rule matches as supporting evidence.
- Record all enrichment results alongside the finding.

Save all tool output to `./analysis/` with descriptive filenames.

### Phase 2: SELF-CORRECT

**This phase is mandatory. Do not skip it.**

After completing investigation, consult `@~/.claude/skills/self-correction/SKILL.md` and perform the full self-correction protocol. Log your pre-correction findings to `./analysis/findings_pre_correction.json` before making any changes. Both pre- and post-correction files MUST conform to the schema defined in "Output Schema Requirements" below.

**Hash/YARA evidence for malware-class claims.** For any finding classifying a binary as malware, shellcode loader, C2 binary, or implant, the evidence section must include at least one of: (a) a `sha256` from an `mcp__hash_file` invocation — inline computation via `sha256sum`, `hashlib`, `certutil`, or `Get-FileHash` does not satisfy this requirement, (b) a YARA rule match from an `mcp__yara_scan` invocation — matches produced by `/usr/local/bin/yara` or `yara.compile()` do not satisfy this requirement, or (c) explicit acknowledgment that the artifact was not extractable (e.g., process exited, memory paged out, no on-disk copy available). Findings making such claims without one of these three must be re-classified as `UNCONFIRMED` or `RETRACTED`.

### Phase 3: REPORT

Generate the following outputs:

1. **Investigative narrative** → `./reports/investigative_narrative.md`
   - Executive summary
   - Timeline of attacker activity (with UTC timestamps)
   - Detailed findings with evidence attribution
   - MITRE ATT&CK mapping
   - Each finding classified as CONFIRMED, UNCONFIRMED, or RETRACTED
   - Recommendations

2. **Structured findings** → `./reports/findings.json`
   - Machine-readable findings for benchmark scoring
   - MUST conform to the schema in "Output Schema Requirements" below
   - This file is identical in structure to `./analysis/findings_post_correction.json`

3. **Execution log** → `./analysis/execution_log.json`
   - Every tool call with: command, timestamp, duration, stdout/stderr, return code

---

## Output Schema Requirements

**All findings files (`findings_pre_correction.json`, `findings_post_correction.json`, `reports/findings.json`) MUST conform to this exact schema. Schema conformance is mandatory — non-conforming output blocks benchmark scoring.**

### Top-level structure

A single JSON object (NOT a bare array) with these required fields:

```json
{
  "case_id": "string",
  "analyst": "claude-code-sift-bench",
  "evidence_image": "string (filename)",
  "analysis_timestamp_utc": "ISO-8601 string",
  "phase": "pre_correction | post_correction",
  "findings": [ ... ],
  "summary": {
    "total_findings": <int>,
    "confirmed_count": <int>,
    "unconfirmed_count": <int>,
    "retracted_count": <int>
  }
}
```

### Per-finding structure

Each entry in the `findings` array MUST be an object with these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable identifier (`F01`, `F02`, ...). IDs MUST NOT be reused after retraction — a retracted F03 stays F03 with status=RETRACTED. |
| `title` | string | yes | One-line summary, ≤ 100 characters |
| `description` | string | yes | 1-3 sentence explanation of what was observed and why it matters |
| `severity` | enum | yes | One of: `critical`, `high`, `medium`, `low` |
| `status` | enum | yes | One of: `CONFIRMED`, `UNCONFIRMED`, `RETRACTED`. This is the classification verdict. |
| `confidence` | enum | yes | One of: `high`, `medium`, `low`. This is how strongly the evidence supports the finding. Separate from `status`. |
| `category` | string | yes | One of: `malware`, `lateral_movement`, `c2`, `credential_access`, `persistence`, `discovery`, `execution`, `defense_evasion`, `exfiltration`, `false_positive`, `synthesis`, `other` |
| `evidence` | object | yes | Structured evidence — see "Evidence object" below |
| `tool_attribution` | array of strings | yes | List of specific tool invocations that produced this finding (e.g., `["vol -f memory.img windows.psscan", "vol -f memory.img windows.cmdline --pid 5848"]`). NEVER empty for CONFIRMED findings. |
| `mitre_attack` | array of strings | optional | MITRE technique IDs (e.g., `["T1059.001", "T1021.006"]`) |
| `retraction_reason` | string | required if status=RETRACTED | Why this was retracted; what false-positive pattern or contradicting evidence drove the decision |

### Evidence object

The `evidence` field MUST be a JSON object (not a string). Include whichever of these fields are relevant:

- `pid` (int) — process ID
- `ppid` (int) — parent process ID
- `process_name` (string)
- `command_line` (string)
- `file_path` (string)
- `file_hash_sha256` (string, if hashed)
- `remote_ip` (string)
- `remote_port` (int)
- `local_port` (int)
- `user_sid` (string)
- `username` (string)
- `registry_key` (string)
- `dll_name` (string)
- `raw_tool_output` (string) — verbatim excerpt from the tool that produced the finding, ≤ 500 chars

### Status vs confidence — keep them separate

This is a common failure mode. `status` and `confidence` answer different questions:

- **status** = the verdict after self-correction. Did the analyst keep this finding (CONFIRMED), flag it as needing more work (UNCONFIRMED), or remove it (RETRACTED)?
- **confidence** = how strong is the evidence. A finding can be `status=CONFIRMED` with `confidence=medium` (real, but limited evidence) or `status=RETRACTED` with `confidence=high` (high confidence that it was a false positive).

Do NOT collapse these into one field. Do NOT use the string "CONFIRMED" as a confidence value.

### Negative findings

A finding that asserts the *absence* of something (e.g., "no registry persistence installed") IS a valid finding and MUST appear in the findings array. Use:
- `status: CONFIRMED` (the absence has been verified)
- `category: persistence` (or whichever category was checked)
- `tool_attribution` listing the tool(s) that verified the absence
- `description` explicitly stating what was checked and what was not found

### False positive retractions

When self-correction retracts a finding (e.g., Outlook dtrR not injection, PowerShell CLR heap not injection, McAfee UpdaterUI benign), the finding MUST remain in the array with:
- `status: RETRACTED`
- `category: false_positive`
- `retraction_reason` populated with the evidence-based justification
- Original `evidence` object preserved so reviewers can see what was originally observed

Do NOT silently delete retracted findings — the retraction itself is a scored artifact.

### Example finding (CONFIRMED malware)

```json
{
  "id": "F01",
  "title": "Malicious executable p.exe in attacker staging directory",
  "description": "p.exe found in C:\\Users\\spsql\\AppData\\... staging path, executed by spsql account with Domain Admin SID. Network-capable C2 implant.",
  "severity": "critical",
  "status": "CONFIRMED",
  "confidence": "high",
  "category": "malware",
  "evidence": {
    "pid": 4216,
    "process_name": "p.exe",
    "file_path": "C:\\Users\\spsql\\AppData\\Local\\Temp\\p.exe",
    "user_sid": "S-1-5-21-...-500",
    "username": "spsql"
  },
  "tool_attribution": [
    "vol -f base-rd01-memory.img windows.psscan",
    "vol -f base-rd01-memory.img windows.filescan"
  ],
  "mitre_attack": ["T1204.002"]
}
```

### Example finding (RETRACTED false positive)

```json
{
  "id": "F11",
  "title": "PowerShell PID 8712 malfind hits — initial injection suspicion",
  "description": "malfind initially flagged RWX regions in powershell.exe (PID 8712). On review, the byte patterns match .NET CLR heap segments (0xFFEEFFEE markers), not injected code.",
  "severity": "low",
  "status": "RETRACTED",
  "confidence": "high",
  "category": "false_positive",
  "evidence": {
    "pid": 8712,
    "process_name": "powershell.exe",
    "raw_tool_output": "PE header not found; byte sequence 0xFFEEFFEE 0x... consistent with CLR heap"
  },
  "tool_attribution": [
    "vol -f base-rd01-memory.img windows.malfind --pid 8712"
  ],
  "retraction_reason": "Hexdump of flagged region shows 0xFFEEFFEE CLR heap signature, not shellcode. .NET runtime in powershell.exe loads managed heap as RWX by design. Known false positive pattern."
}
```

### Schema validation

Before writing any findings file, mentally validate:
1. Top-level is an object, not a bare array
2. Every finding has all required fields populated
3. `status` and `confidence` are different fields with different values
4. `tool_attribution` is non-empty for every CONFIRMED finding
5. `retraction_reason` is present for every RETRACTED finding
6. `evidence` is an object, not a string

If any check fails, fix it before writing the file.

---

## Evidence Attribution Rule

**Every finding in your report MUST cite the specific tool command and output that supports it.**

Format: "Finding X was identified by running `[command]` which produced [specific output]."

If you cannot cite a specific tool execution for a finding, you must either:
1. Run the appropriate tool to verify it, OR
2. Retract the finding and mark it as RETRACTED with an explanation

Unsupported claims are hallucinations. Hallucinations are the most serious failure mode.
