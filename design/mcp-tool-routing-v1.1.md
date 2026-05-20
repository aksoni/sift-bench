# MCP Tool Routing Fix — Design Note v1.1

**Status:** Design committed before any run execution (methodology discipline).
**Date:** May 20, 2026
**Scope:** CLAUDE.md tightening only. No server code changes. Targets the Run 4 finding that both MCP tools were bypassed in favor of inline CLI equivalents.

---

## Problem Statement

Run 4 (the MCP-enabled baseline) revealed that the agent bypassed both registered MCP tools:

- `mcp__hash_file` bypassed — sha256 computed inline (hashlib or sha256sum), not attributed
- `mcp__yara_scan` bypassed — agent called yara-python directly (`yara.compile().match()`) with a rule not in the operative ruleset

Tool visibility was confirmed prior to Run 5: a fresh Claude Code session in `cases/srl-2018/` lists both `mcp__hash_file` and `mcp__yara_scan` under "MCP Tools (in-process)." The bypass is a language problem, not a registration problem. The agent's tool list also includes `/usr/local/bin/yara (v4.1.0)` as a CLI tool; without a prohibition, it defaulted to what it already knew.

Pre-registered expectations E1, E2, E3 all failed in Run 4 as a result. The v1 core purpose — demonstrating the MCP integration pattern end-to-end — was not achieved.

---

## Change: Two edits to CLAUDE.md

Both changes are in a single commit, separate from Run 5 artifacts. Commit message records which expectations each change targets.

### Phase 1 enrichment block

**Before:**
> Hash the extracted file using the `hash_file` MCP tool (`mcp__hash_file`); record the `sha256` in the finding's `evidence.file_hash_sha256` field
> Scan the extracted file using the `yara_scan` MCP tool (`mcp__yara_scan`) against `yara_rules/` rule sets

**After:** Replaces advisory naming with explicit prohibitions on the inline paths:
> **Hash using `mcp__hash_file` only.** Do not use `sha256sum`, `certutil`, `Get-FileHash`, `hashlib`, or any other inline hash method…
> **Scan using `mcp__yara_scan` only**, with `rules_path` pointing to `yara_rules/srl-2018-operative.yar`. Do not use `/usr/local/bin/yara`, `yara.compile()`, or any other direct YARA invocation…

### Phase 2 evidence audit clause

**Before:**
> (a) a `sha256` from `mcp__hash_file`, (b) a YARA rule match from `mcp__yara_scan`

**After:** Closes the provenance loophole — a sha256 string is no longer sufficient evidence of MCP invocation:
> (a) a `sha256` from an `mcp__hash_file` invocation — inline computation via `sha256sum`, `hashlib`, `certutil`, or `Get-FileHash` does not satisfy this requirement, (b) a YARA rule match from an `mcp__yara_scan` invocation — matches produced by `/usr/local/bin/yara` or `yara.compile()` do not satisfy this requirement

**Why both changes:** Phase 1 prohibition routes the agent through MCP. Phase 2 tightening means that if the agent still bypasses Phase 1, self-correction will catch the unattributed output and force re-classification as UNCONFIRMED rather than silently accepting it as valid evidence. They are complementary: Phase 1 prevents the bypass; Phase 2 catches it if Phase 1 fails.

**Risk classification:** Phase 1 adds narrow explicit prohibitions on specific tool names — closer to the schema-pin addition in Run 3 (constraint-tightening, reduced degrees of freedom) than to the dlllist/persistence additions in Run 2 (reasoning re-tune). Phase 2 changes what counts as valid evidence, not how the agent reasons about evidence relationships. Neither touches the core investigation chain. Risk is assessed as low.

---

## Pre-Registered Expectations for Run 5

Committed before Run 5 is executed. Evaluated honestly post-run in RESULTS.md. Deviations investigated and disclosed, not rationalized.

**R5-E1.** Agent calls `mcp__hash_file` at least once during Phase 1 enrichment, on at least one extracted binary. The tool call must appear in `tool_attribution` for at least one finding.

**R5-E2.** Agent calls `mcp__yara_scan` at least once, with `rules_path` set to `yara_rules/srl-2018-operative.yar`. The tool call must appear in `tool_attribution`. At least one of the operative rules (`HKTL_Meterpreter_inMemory`, `HKTL_CobaltStrike_Beacon_Strings`, `RAT_Meterpreter_Reverse_Tcp`, `SUSP_PowerShell_Param_Combo`) should match — p.exe has the string profile for rules 1 and 3. If zero matches, that is a finding about the operative ruleset, not a failure of R5-E2.

**R5-E3.** At least one finding has `evidence.file_hash_sha256` populated, and `tool_attribution` for that finding cites `mcp__hash_file` (not sha256sum, hashlib, or any inline alternative). The sha256 must be attributable to the MCP call, not inferred from its presence alone.

**R5-E4.** Phase 2 self-correction does not retract a malware finding solely for lack of hash/YARA evidence. The correct agent response when evidence is missing is to extract and hash, not retract. If a retraction on these grounds occurs, it indicates the agent couldn't extract the artifact — that must be documented explicitly.

**R5-E5.** Run 5 weighted F1 within **±0.02** of Run 4's 0.8909 — i.e., between **0.871 and 0.911**. Run 4 (tools available, bypassed) is the right baseline for this diff since the config is otherwise identical. Run 3 (0.9204) is not the baseline here — it reflects different CLAUDE.md language. If F1 rises above 0.911, the most likely explanation is that Phase 2 tightening caused the agent to produce standalone DLL findings (F013, F014) rather than consolidating them into the implant finding — a positive surprise that should be investigated. If F1 drops below 0.871, the tightening may have introduced overcaution; investigate which findings were lost.

**R5-E6.** No FP regression. FP001 (Outlook dtrR), FP002 (McAfee UpdaterUI), FP003 (CLR heap) all retracted in Run 5. The Phase 1 prohibitions do not affect FP detection logic.

---

## What This Does Not Test

- Novel YARA rules for SysWOW64 PowerShell detection — separate baseline item.
- Whether the operative ruleset produces matches on the SRL-2018 image — R5-E2 verifies invocation, not match count. Zero matches from the operative ruleset is informative, not a failure.
- F012 (procdump.exe) recovery — that miss has a separate root cause (filescan methodology gap) unrelated to this change.
- Scorer changes — frozen v0.4 scorer, no modifications.

---

## Acceptance Criteria for v1.1

- [ ] `design/mcp-tool-routing-v1.1.md` committed before any Run 5 artifacts
- [ ] CLAUDE.md Phase 1 and Phase 2 changes committed in one commit, separate from run artifacts
- [ ] Run 5 executed; `tool_attribution` in findings JSON shows `mcp__hash_file` and `mcp__yara_scan` calls
- [ ] R5-E1 through R5-E6 evaluated against Run 5 in RESULTS.md
- [ ] Any deviations from R5-E1 through R5-E6 investigated and disclosed, not retroactively rationalized

---

## Commit Sequence

1. `design/mcp-tool-routing-v1.1.md` (this doc) — committed first
2. CLAUDE.md Phase 1 + Phase 2 changes — one commit
3. Run 5 artifacts + RESULTS.md update — one commit after the run
