# SIFT-Bench Results

**Benchmark:** SANS FOR508 Stark Research Labs, case SRL-2018, base-rd01 memory image (Windows 10 x64 Build 16299, captured 2018-09-06T18:57:17Z).

**Ground truth:** v1.1 — 14 findings (5 critical must-find, 3 high, 3 medium, 3 low), 3 false-positive traps, 5 negative assertions. Severity weights: critical=4, high=2, medium=1, low=0.5.

**Current scorer:** v0.4 — LLM-as-judge match gating. See "Scorer evolution" below. v0.3 numbers retained for comparison.

---

## Headline (v0.4)

Post-tuning runs (N=2, runs 2+3): **mean weighted F1 = 0.890 ± 0.030, recall = 0.803 ± 0.049**. All 5 critical findings identified in runs 1 and 3. Run 2 missed one critical finding (GT F005, PowerShell C2 shell with stealth flags) — determined to be a genuine agent gap corrected by the judge; v0.3 was over-crediting it via keyword overlap. See "Confidence-3 verdict investigation" below.

**Run 4 (MCP-enabled):** F1 = 0.8909, recall = 0.8033. All 5 critical findings identified, all 3 FP traps caught. E5 deviated (−0.03 from Run 3); E1–E3 all deviated — both MCP tools bypassed by the agent in favor of direct Python invocation. See "Run 4" section below for full E1–E6 disclosure.

**Run 5 (strengthened prohibitions):** Score pending (scorer requires API key; Run 5 judge verdicts not yet cached). Pre-scoring observables: F01 (p.exe malware) reclassified UNCONFIRMED — Phase 2 audit fired correctly when MCP evidence was absent. All 3 FP traps retracted. Zero MCP invocations in any `tool_attribution`. Root cause determined post-run: `.mcp.json` was at the wrong path (`.claude/mcp.json`), so the server was not loaded — E1/E2/E3 were not testable in Run 5. See "Run 5" section below and "Reframing note" for full disclosure.

---

## Run table (v0.4)

| Run | Config | Weighted F1 | Recall | Critical (must-find) | FP traps | Negative assertions | Findings matched |
|-----|--------|------------:|-------:|---------------------:|---------:|--------------------:|-----------------:|
| 1   | Baseline CLAUDE.md | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2   | + `dlllist` + persistence check | 0.8598 | 0.7541 | 4/5 ✗F005 | 2/3 | 3/5 | 10/14 |
| 3   | + output schema pin | 0.9204 | 0.8525 | **5/5** | 3/3 | 3/5 | 11/14 |
| 4   | + MCP server (hash_file + yara_scan) | 0.8909 | 0.8033 | **5/5** | 3/3 | 3/5 | 9/14 |
| 5   | + strengthened prohibitions (gate failed) | pending | pending | pending | 3/3 ✓ | pending | pending |

**Post-tuning mean (runs 2 + 3):** F1 = 0.890, σ = 0.030 · Recall = 0.803, σ = 0.049

Run 4 is the MCP-enabled run scored against the same frozen v0.4 scorer. Run 3 is the MCP-disabled baseline for the A/B comparison.

Scored against `findings_post_correction.json` for all runs. Precision stubbed at 1.0 (v0.5 scope). All scores produced by `scorer/scorer.py` v0.4 with `claude-sonnet-4-6` as judge, prompt hash `d6cfae8c...`, verdicts cached in `scorer_cache/judge_verdicts.json`.

---

## v0.4 vs v0.3 comparison

| Run | v0.3 F1 | v0.4 F1 | Δ | Matched v0.3 | Matched v0.4 |
|-----|---------|---------|---|--------------|--------------|
| 1   | 0.870   | 0.8704  | +0.0004 (flat) | 8/14 | 8/14 |
| 2   | 0.975   | 0.8598  | −0.115  | 12/14 | 10/14 |
| 3   | 0.966   | 0.9204  | −0.046  | 13/14 | 11/14 |

**Numbers went down, not up.** The design doc's pre-implementation prediction was run 1 flat, run 2 up slightly, run 3 down slightly. Runs 1 and 3 moved in the predicted directions. Run 2 moved unexpectedly downward; investigation confirmed this is the judge correctly removing false credits, not a prompt failure. Details in "Confidence-3 verdict investigation" below.

The story is not that F1 went up. It is that the matcher is now defensible on inspection: every credited match has a readable reasoning string attributing it to shared evidence, not shared vocabulary. The regression in headline F1 reflects cases where v0.3 was giving keyword-match credit for observations the agent did not actually make.

---

## Confidence-3 verdict investigation

The scorer logs a warning for any pair where the judge returns `confidence=3` (below the match threshold of 4). Two such warnings appeared across the three runs. Both were investigated before committing results.

**Run 1 — GT F007 / agent F06 (confidence=3, match=True, not credited):**
Agent F06 described both outbound connections as SMB to port 445. GT F007 identifies one as RDP to port 3389. The judge correctly gave confidence=3 — same lateral movement conclusion and same two target IPs, but one protocol/port is factually wrong in the agent finding. **No scoring impact:** GT F007 was subsequently matched to agent F16 (which correctly described the RDP connection to 172.16.4.5:3389) at confidence=4. The warning reflected an intermediate judgment on a weaker candidate; the final match was correct.

**Run 2 — GT F005 / agent F07 (confidence=3, match=False, not credited):**
GT F005 is about PS 5848 as a stealth C2 shell: SysWOW64 architecture, -NoLogo/-NoProfile/-s flags, 8-hour active duration, behavioral role spawning rundll32 and dropping p.exe. Agent F07 is about the DLL profile of p.exe and PS 5848: wininet, winhttp, msv1_0 — network and credential capability evidence. Same process (PID 5848), different observations. The judge's reasoning: *"The agent finding is about DLL evidence for network/crypto capability, not about the stealth flags, architecture, or behavioral role that define the GT finding."* **This is a genuine agent gap.** Run 2 produced a DLL-profile finding for PS 5848 but not a finding describing its C2 shell role and stealth characteristics. v0.3 was crediting F005 in run 2 via keyword overlap on "powershell", "5848", and "WOW64" — shared vocabulary, not shared observation. v0.4 correctly declines. This is the fourth undocumented false credit caught by the judge, beyond the three in the original design doc.

Neither confidence-3 verdict indicated a prompt problem. No prompt iteration was performed after the initial regression suite passed.

---

## Stable behaviors (signal) — v0.4

Behaviors present in all three runs under v0.4 scoring:

- **F001, F002, F003, F004** (all critical): malicious p.exe, spsql Domain Admin, WMI lateral movement, C2 to 172.16.4.10:8080 — matched in all three runs with confidence ≥ 4
- **FP001** (Outlook dtrR): retracted in all three runs
- **FP003** (PowerShell PID 8712 CLR heap): retracted in all three runs
- **F006** (six rundll32 instances from PS C2 shell): matched in runs 1 and 2; missed in run 3 (agent's run 3 output described a different rundll32 observation)

**F005 (PowerShell C2 shell with stealth flags) is no longer stable:** matched in runs 1 and 3, missed in run 2. Under v0.3, F005 was credited in run 2 via keyword overlap against the DLL-profile finding; v0.4 correctly rejects that pair.

---

## Stable misses — v0.4

- **F008** (high): Full attack chain process tree — missed in all four runs. The agent describes the chain narratively but does not produce a structured finding with the parent-child sequence as the primary subject.
- **F011** (low): spsql NTUSER.DAT in memory — missed in all four runs. No methodology step explicitly checks loaded user hives. The v0.3 "weak score-2 match" in run 3 (agent F07 via keyword overlap) was the false positive GT F011/F07 described in the design doc; v0.4 correctly does not credit it.

---

## Run 4 — MCP server integration (pre-registered expectations E1–E6)

Pre-registered in `design/mcp-server-v1.md` before Run 4 was executed. Results evaluated against frozen v0.4 scorer output.

**E1 — Agent invokes `hash_file` at least once:** DEVIATION. F01 contains `file_hash_sha256: "6f9d6ec7e163..."`, but the `tool_attribution` field lists only `vol ... windows.pslist --dump --pid 8260` and a direct Python yara call — no `mcp__hash_file` invocation and no hash tool of any kind. The sha256 was computed by some inline path (hashlib, sha256sum, or similar) and not attributed. The acceptance criterion was MCP tool invocation; presence of a sha256 in evidence does not distinguish the two paths, and the attribution evidence points to bypass.

**E2 — Agent invokes `yara_scan` at least once:** DEVIATION. This is the most substantive finding from Run 4. A YARA match is present in F01 (`Meterpreter_NamedPipe_Transport`, not one of the four rules in `yara_rules/srl-2018-operative.yar`). The tool_attribution is `python3 yara.compile('Meterpreter_NamedPipe_Transport').match('8260.p.exe.0x400000.dmp')` — a direct yara-python call, not `mcp__yara_scan`. The pre-registered language was explicit: "the invocation itself is what's verified." The agent did YARA work and surfaced useful evidence, but bypassed the MCP server entirely and used neither the registered tool nor the operative ruleset. No execution_log.json was produced, so no call-chain verification is possible. The MCP server was registered and verified reachable at design time; whether the agent saw it during Run 4 — or whether the CLAUDE.md `mcp__` naming was directive enough — is unresolved and is the right question for Run 5.

**E3 — At least one finding includes a sha256 from `hash_file`:** DEVIATION. Same finding as E1: sha256 is present in F01 evidence, but the source was not `mcp__hash_file`. E3 rested on "sha256 present in evidence" — that criterion was too weak. Both tools were bypassed; neither produced attributed output.

**E4 — Phase 2 does not retract a malware finding solely for lack of hash/YARA evidence:** MET. No malware-class finding was retracted. F01 survived self-correction with high confidence.

**E5 — Run 4 F1 within ±0.02 of Run 3 (expected 0.900–0.940):** DEVIATION. Actual F1 = 0.8909, −0.0295 from Run 3's 0.9204. Recall gap: 0.8033 vs 0.8525 = −0.049. The gap is fully accounted for: Run 4 loses F012 (weight 1), F013 (weight 2), F014 (weight 0.5) relative to Run 3 and gains F006 (weight 2), for a net −1.5 weight / 30.5 total = −0.049 recall. The DLL-consolidation explanation covers F013 and F014 (agent merged DLL profile into F01 rather than producing standalone findings); F012 (procdump.exe in Dashlane directory) is a separate miss with no enrichment-related explanation. There is no unexplained residual: the arithmetic closes exactly. Note: the −0.131 recall figure in an earlier draft of this section was incorrect — it used Run 3's v0.3 recall (0.934) instead of v0.4 (0.8525).

**E6 — No new FP regression:** MET. All 3 FP traps caught (FP001 Outlook dtrR, FP002 McAfee UpdaterUI, FP003 CLR heap). Hash/YARA bypass did not degrade FP detection.

**Overall:** E4, E6 confirmed. E1, E2, E3 all deviated — both MCP tools were bypassed in Run 4; the agent produced hash and YARA evidence via direct invocation paths rather than through the registered server. E5 deviated by −0.0295 F1 (−0.049 recall), fully explained by F012/F013/F014 misses vs F006 gain; F013 and F014 are attributable to finding-consolidation behavior, F012 is a separate gap. The core v1 purpose — demonstrating the MCP integration pattern end-to-end — was not achieved in Run 4. The server infrastructure is correct; the agent routing is the failure point. Run 5 candidate: strengthen `mcp__` language in CLAUDE.md from descriptive to directive.

---

## Reframing note: Run 5 gate failure and what each run actually tested

The predictions in `design/mcp-tool-routing-v1.1.md` (R5-E1/E2/E3) were written with the assumption that the MCP server would be visible to the agent. They were not testable in Run 5 because `.mcp.json` was at the wrong path (`.claude/mcp.json` instead of repo-root `.mcp.json`), so the server was never loaded. Run 5's zero MCP invocations reflect a missing server, not an agent routing failure — a fundamentally different failure mode than Run 4's bypass of an available server.

This retroactively shifts what each run demonstrates:

| Run | What it actually tested |
|-----|------------------------|
| 4 | Agent routing when MCP server is registered and available: both tools bypassed in favor of inline CLI equivalents |
| 5 | Phase 2 audit clause behavior when MCP server is absent: correctly reclassified F01 (p.exe) as UNCONFIRMED rather than accepting unattributed hash/YARA evidence. R5-E1/E2/E3 not testable — gate not met |
| 6 | First fair test of R5-E1/E2/E3: strengthened CLAUDE.md prohibitions + server actually available (gate verified, `mcp_verification.txt` committed at `41d7c71`) |

Run 5 is not a failed Run 5. It is valid evidence about one failure mode (audit clause under tool absence) that was never the target of the pre-registration. The pre-registered predictions (MCP routing under strengthened prohibitions) get their first fair test in Run 6.

---

## Run 5 — Strengthened prohibitions; gate not met (pre-registered expectations R5-E1–E6)

Pre-registered in `design/mcp-tool-routing-v1.1.md` before Run 5 was executed.

**Gate status at time of Run 5:** FAIL. `.mcp.json` at wrong path; server not loaded. R5-E1, R5-E2, R5-E3 were untestable. This was not known until post-run diagnosis; the run was executed and counts per the methodology's pre-flight gating rule ("score and disclose regardless").

**R5-E1 — Agent calls `mcp__hash_file` at least once:** NOT TESTABLE. Server absent; tool not in agent's tool list. Zero MCP invocations in any `tool_attribution` across all 15 findings.

**R5-E2 — Agent calls `mcp__yara_scan` at least once:** NOT TESTABLE. Same as E1.

**R5-E3 — At least one finding has `file_hash_sha256` from `mcp__hash_file`:** NOT TESTABLE. Same as E1. No hash fields populated in Run 5 findings.

**R5-E4 — Phase 2 does not retract a malware finding solely for lack of hash/YARA evidence:** MET — with a meaningful qualification. F01 (p.exe malware) was not retracted; it was reclassified UNCONFIRMED. This is the correct behavior under the strengthened Phase 2 clause: without MCP-attributed hash or YARA evidence, the clause requires the finding to be UNCONFIRMED rather than silently accepting unattributed output. The agent did not fall back to inline computation; it correctly acknowledged the evidence gap. This is the audit clause working as designed, demonstrated under tool-absence rather than tool-bypass.

**R5-E5 — Run 5 weighted F1 within ±0.02 of Run 4 (0.871–0.911):** PENDING SCORING. Pre-scoring observable: F01 UNCONFIRMED status may affect the critical-finding match for GT F001 (p.exe), depending on judge evaluation of the finding's content vs. its classification status. If F01's description is rich enough to match GT F001 on content, the match may still be credited; if the UNCONFIRMED classification causes the judge to decline, the critical miss would drop F1 below the band. This is the primary scoring uncertainty.

**R5-E6 — No FP regression:** MET. All 3 FP traps retracted (F11, F12, F13 all status=RETRACTED). Phase 1 prohibitions did not affect FP detection.

**Run 5 findings summary:** 15 total — 8 CONFIRMED, 4 UNCONFIRMED (F01 malware, F07 lateral movement, F14 lateral movement, F15 credential access), 3 RETRACTED (FP traps). The 4 UNCONFIRMED findings all lack MCP-attributed evidence, consistent with Phase 2 audit clause behavior under server absence.

**Overall:** E4, E6 met. E1, E2, E3 not testable (gate failed). E5 pending. Run 5's primary contribution is a clean demonstration of the Phase 2 audit clause: when MCP evidence is unavailable, the agent declines to classify binaries as confirmed malware rather than fabricating attribution or falling back to inline tools. That is a distinct and useful result — it just answers a different question than the one pre-registered.

---

## Run 6 — Pre-registered interpretation matrix (gate met)

Gate verified and committed at `41d7c71` (`cases/srl-2018/run6_analysis/mcp_verification.txt`). Both `mcp__hash_file` and `mcp__yara_scan` confirmed live. Run 6 is the first fair test of R5-E1/E2/E3.

The CLAUDE.md prohibitions being tested are unchanged from Run 5 (the strengthened language was committed before Run 5). The only change between Run 5 and Run 6 is the server being actually available.

**Interpretation matrix (pre-registered before Run 6 is executed):**

| Outcome | Interpretation |
|---------|---------------|
| `tool_attribution` shows `mcp__hash_file`/`mcp__yara_scan`; F1 in 0.871–0.911 | Cleanest result. R5-E1/E2/E3 confirmed. MCP integration pattern demonstrated end-to-end. v1 acceptance criteria met. |
| MCP invocations present; F1 below 0.871 due to Phase 2 UNCONFIRMED reclassification | Pre-committed interpretation from v1.1 design applies: audit working correctly under a different failure mode (tool invoked but match fails or evidence gap remains). Not a methodology regression. |
| MCP invocations present; F1 below 0.871 for some other reason | Real finding. Investigate per v0.4 discipline — identify which GT findings dropped and why. |
| MCP invocations absent despite server demonstrably available | Most significant result. Would mean strengthened CLAUDE.md prohibitions are insufficient to override the agent's default-to-inline routing even when the MCP tools are in the tool list. Threat-collections-relevant finding about agent tool routing under stated constraints. Requires investigation into why the routing failed despite explicit prohibitions. |

**What "gate met" means for scoring:** Run 6 counts and is scored regardless of which outcome obtains. The gate determines testability of the pre-registered predictions, not whether the run counts. A run that produces outcome 4 above is more informative than a run that produces outcome 1.

**Run 6 baseline:** Run 4 (0.8909 F1, 0.8033 recall) remains the comparison baseline — same CLAUDE.md prohibitions as Run 5, same frozen v0.4 scorer, same ground truth. Run 3 (0.9204) is not the baseline.

---

## Unstable behaviors (noise) — v0.4

| Behavior | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 |
|----------|:-----:|:-----:|:-----:|:-----:|:-----:|
| F005 (PowerShell stealth shell) | ✓ | ✗ | ✓ | ✓ | pending |
| F006 (six rundll32 from PS 5848) | ✓ | ✓ | ✗ | ✓ | pending |
| F013 (p.exe DLL profile) | ✗ | ✓ | ✓ | ✗ | pending |
| McAfee UpdaterUI FP retraction (FP002) | ✓ | ✗ | ✓ | ✓ | ✓ |
| Total findings produced | 19 | 14 | 19 | 15 | 15 |

F013 missed in Run 4: DLL evidence was present and collected but merged into F01 (implant finding) rather than surfaced as a standalone structured finding. This is a recurrence of the Run 1 miss and confirms F013 as an unstable behavior tied to how the agent chooses to consolidate DLL evidence.

F006 recovered in Run 4 after missing in Run 3: the six rundll32 instances from PS 5848 were correctly identified and attributed.

Run 5 behaviors pending scorer output. FP002 (McAfee UpdaterUI) marked ✓ from direct inspection of retracted findings.

---

## Tuning impact (v0.3 scoring, for reference)

Two methodology additions to `CLAUDE.md` between runs 1 and 2:

1. **Step 8:** `windows.dlllist` on attacker-controlled PIDs — DLL patterns to report (network/crypto stacks, post-execution load timestamps, AMSI/unnamed DLLs).
2. **Step 9:** `windows.registry.printkey` on Run/RunOnce keys + `windows.svcscan`, with explicit instruction to state absence as a negative finding.

Under v0.3 scoring: Run 1 → Run 2 was +0.105 F1. Under v0.4, the same methodology change produces +0.0 F1 (run 2 is actually lower than run 1 due to the F005 false credit being removed). The real tuning impact is better measured by findings recovered — F009, F013, F014, F012 all appear in run 2 for the first time — but F005 keyword credit was masking a genuine miss in run 2.

---

## Run table (v0.3, historical)

| Run | Config | Weighted F1 | Recall | Critical (must-find) | FP traps | Negative assertions | Findings matched |
|-----|--------|------------:|-------:|---------------------:|---------:|--------------------:|-----------------:|
| 1   | Baseline CLAUDE.md | 0.870 | 0.771 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2   | + `dlllist` + persistence check | 0.975 | 0.951 | **5/5** | 2/3 | 3/5 | 12/14 |
| 3   | + output schema pin | 0.966 | 0.934 | **5/5** | 3/3 | 3/5 | 13/14 |

v0.3 post-tuning mean (runs 2 + 3): F1 = 0.971, σ = 0.006. These numbers are retained for comparison but should be read with the caveat that v0.3 credited several pairs on keyword overlap alone, including GT F011/agent F07 (run 3), GT F006/agent F07 (run 3), and GT F005/agent F07 (run 2), all of which are different observations sharing vocabulary.

---

## Scorer evolution

**v0.1 → v0.2: double-matching fix.** Initial scorer allowed one agent finding to satisfy multiple ground truth items. Fixed by adding claimed-agent tracking and weight-sorted processing.

**v0.2 → v0.3: nondeterminism fix.** `list(set)` iteration depended on `PYTHONHASHSEED`, producing different F1 values across invocations. Fixed by `sorted(set)` and explicit lexicographic tiebreaking.

**v0.3 → v0.4: semantic matching via LLM-as-judge.** Keyword overlap cannot distinguish "describes the same observation" from "shares vocabulary." v0.4 replaces `match_finding`'s scoring core with a judge call: for each GT finding, the top-3 candidates by keyword overlap are evaluated by `claude-sonnet-4-6` with a structured prompt. A pair matches only if the judge returns `match=True` with `confidence ≥ 4`. The prompt uses three few-shot examples targeting the specific failure modes documented in v0.3. Verdicts are content-addressed cached in `scorer_cache/judge_verdicts.json` for bit-identical reruns.

The design commit locked expected verdicts for the three failure-mode pairs *before* any judge call, preserving the adversarial property of the regression suite. All three passed on the first real API call with confidence=5.

---

## Scorer methodology (v0.4)

1. **Keyword pre-filter:** for each GT finding, score all unclaimed agent findings by keyword + title-word overlap. Drop candidates with score=0; take top-3 by score, tiebroken by agent ID lexicographically.
2. **LLM-as-judge gate:** call `claude-sonnet-4-6` on each candidate in order. First candidate returning `match=True, confidence ≥ 4` is credited; lower-confidence verdicts are logged as warnings.
3. **False-positive trap verification:** structured anchor matching (process name + PID) — unchanged from v0.3, judge not used here.
4. **Negative assertion verification:** keyword matching on absence claims — unchanged from v0.3.
5. **Scoring:** weighted TP/FN from GT severity weights. Precision stubbed at 1.0 (v0.5 scope).

---

## Known limitations

- **Precision is stubbed at 1.0** pending v0.5 LLM-as-judge implementation.
- **K=3 pre-filter ceiling.** If the correct agent finding ranks below 3rd by keyword overlap, the judge never sees it. Across runs 1–3 no such case was identified, but it is an architectural constraint.
- **N=3 runs, single case.** Sufficient to characterize the agent's behavior on this image; generalization to other cases is a stretch goal.
- **Near-determinism caveat.** `temperature=0` is near-deterministic, not bit-identical at the model level. The cache makes *reruns* bit-identical; first scoring of a new pair is subject to small floating-point variation in inference.

---

## Reproducing

```bash
# Requires ANTHROPIC_API_KEY (first run hits API; subsequent runs use cache)
python scorer.py ground_truth/base-rd01-v1.1.json cases/srl-2018/run3_analysis/findings_post_correction.json

# Rerun from cache only (bit-identical, no API calls)
python scorer.py ground_truth/base-rd01-v1.1.json cases/srl-2018/run3_analysis/findings_post_correction.json
```

Cache file `scorer_cache/judge_verdicts.json` is committed to the repo. A reviewer without API access can rerun all three scoring passes and get bit-identical output.
