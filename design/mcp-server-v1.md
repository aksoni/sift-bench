# MCP Server v1: Design Note

**Status:** Design committed before any MCP code (per scorer-v0.4 discipline).
**Date:** May 19, 2026
**Scope:** v1 baseline. v1.1 / stretch items called out explicitly at the bottom.

---

## Goal

Build a single MCP server, registered with Claude Code, that exposes two file-operation tools to the agent:

- `hash_file(path)` — return md5/sha1/sha256 + size for a file on disk
- `yara_scan(target_path, rules_path, timeout_seconds)` — compile a YARA ruleset and scan a single file, returning structured matches

Integrate via two hooks: opportunistic in Phase 1 (enrichment), constraint-tightening in Phase 2 (evidence audit raises the evidentiary bar for malware-class claims). Demonstrate end-to-end with one agent run (Run 4) scored against frozen v0.4 ground truth and scorer.

v1 deliberately does not implement VT / Censys / external-API tools. It implements the *integration pattern* with two locally-actionable tools so the extension path is obvious.

---

## Scope

**In v1:**
- One MCP server (`mcp_server/` package) exposing `hash_file` and `yara_scan` over stdio.
- Structured error returns (no raw exceptions across the MCP boundary).
- Self-test script (`tests/test_mcp_server.py`) covering each tool against a known fixture with deterministic expected output.
- Minimal CLAUDE.md additions: name the tools in Phase 1 enrichment language; add one Phase 2 evidence-audit clause for malware-class findings.
- One agent run (Run 4) with MCP server enabled, evidence of tool invocations captured in the run's findings JSON.
- Run 4 scored using the frozen v0.4 scorer (no scorer code changes), documented in RESULTS.md with pre-registered-vs-actual comparison.

**Deferred to v1.1 (only after baseline ships):**
- Content-addressed `yara_scan` result cache keyed on `(target_sha256, rules_sha256, yara_version)`. The tool's output already exposes `target_sha256` and `rules_sha256`, so a future cache layer wraps the function without API changes.
- Directory recursion in `yara_scan`.
- Compiled `.yarc` ruleset support.
- Multi-rule-file loading.

**Out of scope for this server (separate work items, not stretch):**
- Novel SysWOW64 PowerShell YARA rule (next baseline item; ships in its own commits).
- `tool_executor.py` guardrails layer.
- VirusTotal / Censys / external-API MCP tools.
- A/B baseline comparison rerun with MCP disabled. **Run 3 is the MCP-disabled baseline** (no MCP server existed at scoring time). Run 4 is the MCP-enabled comparison. No second pass needed.

**Frozen, do not touch:** `scorer/`, `design/scorer-v0.4.md`, `scorer_cache/judge_verdicts.json`. v0.4 ships as-is.

---

## Architecture

**Single server, two tools.** Single process, single MCP registration entry in CLAUDE.md, both tools are file-input enrichment with similar lifecycle. Extension story for future external-API tools is "add a tool to this server," not "deploy another server."

**Layout:**
```
mcp_server/
├── __init__.py
├── __main__.py        # entry: `python -m mcp_server`; wires MCP stdio + tools
├── server.py          # MCP protocol handlers, tool registration
└── tools.py           # hash_file + yara_scan implementations (pure functions)
tests/
└── test_mcp_server.py # local invocation tests; no Claude Code dependency
```

**Transport:** stdio. Standard for Claude Code MCP integration; matches the local-process model.

**Dependencies:** `mcp` (official Python SDK), `yara-python`. `hashlib` is stdlib. Add to `requirements.txt` alongside `anthropic`.

**Invocation from Claude Code:** registered in `.claude/mcp.json` at the project root (`~/sift-bench/.claude/mcp.json`) with command `python3 -m mcp_server`, working directory `~/sift-bench/`. *(See amendment note at end of document — original design specified the case-scoped path `cases/srl-2018/.claude/mcp.json`.)*

---

## Tool Specifications

### `hash_file`

**Signature:**
```
hash_file(path: str) -> {
    "path": str,
    "size_bytes": int,
    "md5":    str,   # hex, lowercase
    "sha1":   str,
    "sha256": str
}
```

**Behavior:** Stream-read the file in 1 MiB blocks; update all three hashers in a single pass. Return all three on success — they're effectively free given the I/O is the cost. Multiple hash types are useful for cross-referencing across threat-intel sources (VT/etc.) in future work, and demonstrate the "disparate signals" pattern in the role mapping.

**Structured errors** (returned as `{"error": <code>, "path": ..., "detail": ...}`, never raised exceptions across the MCP boundary):
- `file_not_found`
- `permission_denied`
- `not_a_regular_file` (directory, device, broken symlink)

**No size cap.** Memory image is 3GB and the agent may legitimately want to hash it; streaming handles that without RAM pressure.

---

### `yara_scan`

**Signature:**
```
yara_scan(target_path: str, rules_path: str, timeout_seconds: int = 30) -> {
    "target_path":   str,
    "target_sha256": str,
    "rules_path":    str,
    "rules_sha256":  str,
    "matches": [
        {
            "rule":      str,
            "namespace": str,
            "tags":      [str],
            "meta":      { <key>: <value> },
            "strings":   [
                { "identifier": str, "offset": int, "data": str }   # data is lowercase hex
            ]
        }
    ],
    "scan_duration_ms": int
}
```

**Behavior:**
- Compile `rules_path` (single `.yar` source file) via `yara.compile`.
- Scan `target_path` (single regular file) via `rules.match(filepath=...)`.
- Convert matched-string `data` bytes to lowercase hex always. Never attempt utf-8 decode — it's lossy and inconsistent across rules.
- Compute `target_sha256` and `rules_sha256` in-band so future caching has a stable key without re-reading either input. Cost is negligible relative to the scan.

**Structured errors:**
- `target_not_found`, `target_not_a_regular_file`
- `rules_not_found`
- `rules_compile_error` (compile error string in `detail`)
- `scan_timeout` (timeout enforced via threaded interrupt; partial matches **not** returned for v1 — timeout means "no result"; elapsed time included in detail)

**`scan_duration_ms`** is always returned on success.

**v1 restriction: single regular file target only.** No directory walking. Keeps the failure modes small. Directory targets are easy to add in v1.1 once the scanning surface is exercised in Run 4.

---

## Integration with the 3-Phase Workflow

CLAUDE.md is tuned. Changes here are deliberately small and additive — name the tools, attach them to existing checklist items, do not refactor structure. Each Phase change is one sentence-to-paragraph.

### Phase 1 (INVESTIGATE + ENRICH)

Existing language already says enrichment uses MCP tools "when available." Minimal change: name the tools and give one usage cue.

**Proposed addition** (single sentence appended to the relevant Phase 1 enrichment step):

> When binaries of interest are extractable (`procdump`, `dumpfiles`), invoke `mcp__hash_file` on the dumped path and include the sha256 in the finding's evidence; invoke `mcp__yara_scan` against the provided ruleset and include any rule matches as supporting evidence.

### Phase 2 (SELF-CORRECT)

The substantive addition. Append **one** item to the evidence audit checklist:

> **Hash/YARA evidence for malware-class claims.** For any finding classifying a binary as malware, shellcode loader, C2 binary, or implant, the evidence section must include at least one of: (a) a sha256 from `mcp__hash_file`, (b) a YARA rule match from `mcp__yara_scan`, or (c) explicit acknowledgment that the artifact was not extractable (e.g., process exited, memory paged out, no on-disk copy available). Findings making such claims without one of these three must be re-classified as UNCONFIRMED or RETRACTED.

**Why this is lower-risk than the dlllist/persistence additions** that drove the run 1 → run 2 +0.105 F1 jump: this is constraint-tightening on a specific claim subclass, not a behavioral re-tune. It raises the evidentiary bar; it doesn't change how the agent reasons about evidence.

### CLAUDE.md commit hygiene

CLAUDE.md update is its **own commit**, separate from MCP server code. Reason: if Run 4 surfaces a behavior change attributable to CLAUDE.md vs the tools themselves, the git history lets us isolate which one.

---

## Methodology Carry-Overs from v0.4

**Design before code.** This doc. Committed first.

**Commit hygiene (no squashing).** Planned commit sequence:

1. `design/mcp-server-v1.md` (this doc) — committed before any MCP code commit.
2. `mcp_server/` scaffold + `hash_file` + `tests/test_mcp_server.py::test_hash_file`.
3. `yara_scan` + `tests/test_mcp_server.py::test_yara_scan` (incl. error paths).
4. CLAUDE.md Phase 1 + Phase 2 additions.
5. Run 4 artifacts (`cases/srl-2018/run4_analysis/`, `run4_reports/`) committed.
6. RESULTS.md update with Run 4 numbers + pre-registered-vs-actual evaluation.

If iteration on a tool signature happens mid-implementation, those land as additional commits — not amended into earlier commits.

**Pre-register expectations.** See next section. v0.4 disclosure pattern applies: prediction wrong → investigate and document, don't rationalize.

**Content-addressed reproducibility where it matters.** Deferred for v1 (`yara_scan` caching is v1.1), but tool output already includes `target_sha256` and `rules_sha256` so the data layer for a future cache is in place without an API change.

---

## Pre-Registered Expectations for Run 4

Committed before Run 4 is executed. Evaluated honestly post-run in RESULTS.md, regardless of direction. v0.4-style: discrepancies investigated and disclosed, not retroactively rationalized.

**E1.** Agent invokes `hash_file` at least once during Phase 1, on at least one binary it identifies as suspicious (most likely p.exe given F001's centrality).

**E2.** Agent invokes `yara_scan` at least once if a ruleset is provided. v1 ruleset is whatever community/test rules are loaded — the novel SysWOW64 rule is not in scope yet, so `yara_scan` may produce zero matches; the **invocation itself** is what's verified, not the match count.

**E3.** At least one finding (most likely F001 p.exe) has its evidence section include a sha256 string produced by `hash_file`.

**E4.** Phase 2 self-correction does **not** retract a previously-confirmed malware finding solely for lack of hash/YARA evidence. Justification: p.exe and similar artifacts are extractable in this case; the correct agent response is to extract and hash, not retract.

**E5.** Run 4 v0.4 F1 stays within **±0.02** of Run 3's 0.9204 — i.e., between 0.900 and 0.940. Justification: the known stable miss (F011 NTUSER.DAT) is a methodology gap, not hash/YARA-related. F1 movement attributable to MCP integration should be small. Any movement larger than ±0.02 in either direction is a finding and gets investigated and disclosed.

**E6.** No new false-positive trap regression. FP001 (Outlook dtrR), FP002 (McAfee UpdaterUI), FP003 (CLR heap) all still caught in Run 4. Hash/YARA tools add evidence channels; they should not degrade FP detection.

Predictions evaluated using the frozen v0.4 scorer. **No scorer code changes for Run 4.**

---

## v1 Acceptance Criteria

- [ ] `design/mcp-server-v1.md` committed before any `mcp_server/` code commit (git log proof)
- [ ] `mcp_server/` package implements both tools with structured error returns over stdio
- [ ] `tests/test_mcp_server.py` passes locally:
  - `test_hash_file`: hashes of a small committed text fixture match expected md5/sha1/sha256
  - `test_yara_scan`: scan of a known-positive fixture with a trivial rule (e.g., `rule TestMarker { strings: $a = "FIND_EVIL_MARKER" condition: $a }`) produces the expected match; scan with a non-matching rule produces empty matches
  - error paths exercised: missing target, missing rules, rules compile error, not-a-regular-file
- [ ] MCP server registered with Claude Code in `.claude/mcp.json` at the project root (`~/sift-bench/.claude/mcp.json`), verified by invoking each tool manually from a fresh Claude Code session
- [ ] CLAUDE.md updated (Phase 1 + Phase 2) and committed separately from server code
- [ ] Run 4 executed end-to-end; findings JSON shows evidence of at least one `hash_file` invocation and one `yara_scan` invocation
- [ ] Run 4 scored with frozen v0.4 scorer; numbers added to RESULTS.md alongside Runs 1-3
- [ ] Pre-registered expectations E1–E6 evaluated against Run 4 in RESULTS.md, with any deviations investigated and disclosed

---

## v1.1 Candidates and Explicit Non-Goals

**v1.1 candidates (only after v1 baseline ships):**
- Content-addressed `yara_scan` cache at `mcp_cache/yara_scans.json`, key = `sha256(target_sha256|rules_sha256|yara_version)`
- Directory recursion for `yara_scan` targets
- Compiled `.yarc` ruleset support
- Multi-rule-file loading via `rules_paths: list[str]`

**Explicit non-goals for the entire June 15 submission unless baseline lands well ahead of schedule:**
- VirusTotal / Censys / external-API tools on this server
- MCP server as a remotely-hosted service (local stdio only)
- Persistent state in the server beyond optional caching
- Tool calling from non-Claude-Code MCP hosts

The novel SysWOW64 PowerShell YARA rule is **not** part of MCP v1 but is the next baseline item after this. It depends on this server existing, and it ships independently with its own test cases and design considerations.

---

## Amendment: MCP registration path

**Original design:** `cases/srl-2018/.claude/mcp.json`

**Actual implementation:** `~/sift-bench/.claude/mcp.json` (project root)

**Reason:** During implementation it was confirmed that Claude Code's project-root convention (`<repo>/.claude/mcp.json`) is the documented, version-stable pickup location. Case-scoped config pickup (`cases/srl-2018/.claude/`) is version-dependent and unreliable for reviewers on different Claude Code versions. Project-root placement preserves repo portability — reviewers cloning the repo get the registration without any path edits — and is discovered when Claude Code is launched from any subdirectory of `~/sift-bench/`, including the case directory.

No change to tool specs, phase integration, or pre-registered expectations E1–E6.
