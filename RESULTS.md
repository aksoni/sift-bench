# SIFT-Bench Results

**Benchmark:** SANS FOR508 Stark Research Labs, case SRL-2018, base-rd01 memory image (Windows 10 x64 Build 16299, captured 2018-09-06T18:57:17Z).

**Ground truth:** v1.1 — 14 findings (5 critical must-find, 3 high, 3 medium, 3 low), 3 false-positive traps, 5 negative assertions. Severity weights: critical=4, high=2, medium=1, low=0.5.

**Current scorer:** v0.5 — LLM-as-judge match gating + **real evidence-traceability precision** + per-pair fallback + content-addressed cache keys. All 6 runs re-scored 2026-05-29 (see "v0.5 re-scoring" below). v0.4 and v0.3 numbers retained for comparison. The v0.4 → v0.5 change also corrects the Run 6 F006 misdiagnosis (cache-key collision, not K=3 keyword competition — see "F006 correction" below).

**Metric note (v0.5):** Precision is now *computed* via an evidence-traceability judge rather than stubbed. It came out **1.0 for all six runs** because the judge found zero illegitimate unclaimed findings — every unclaimed agent finding was either evidence-supported-but-out-of-GT-scope ("legit-unmatched") or below the confidence-4 bar ("uncertain"). So `weighted_f1` still tracks severity-weighted recall in practice, but the 1.0 precision is now substantiated, not assumed. Precision is count-based while recall is severity-weighted, so `weighted_f1` is a documented asymmetric hybrid, not a single-scheme F1.

---

## v0.5 re-scoring (current)

Pre-registered in `design/scorer-v0.5.md` (committed 2026-05-21, before any v0.5 code). All 6 runs
re-scored 2026-05-29 against `ground_truth/base-rd01-v1.1.json` with `claude-sonnet-4-6` as judge.
Content-addressed cache keys invalidate every v0.4 cache entry, so this was a 100% cache-miss
regeneration; the resulting verdicts are committed in `scorer_cache/judge_verdicts.json` for
key-free reproduction. Full prediction evaluation in `analysis/v05_rescoring/predictions_eval.md`.

### Run table (v0.5)

| Run | Config | v0.5 F1 | Recall¹ | Precision² | Critical (must-find) | FP traps | Findings matched | F006 |
|-----|--------|--------:|--------:|-----------:|---------------------:|---------:|-----------------:|:----:|
| 1   | Baseline CLAUDE.md | 0.8704 | 0.7705 | 1.0000 | **5/5** | 3/3 | 8/14  | ✓ primary |
| 2   | + `dlllist` + persistence check | 0.8598 | 0.7541 | 1.0000 | 4/5 ✗F005 | 2/3 | 10/14 | ✓ primary |
| 3   | + output schema pin | 0.9107 | 0.8361 | 1.0000 | **5/5** | 3/3 | 10/14 | ✗ (genuine gap) |
| 4   | + MCP server | 0.8909 | 0.8033 | 1.0000 | **5/5** | 3/3 | 9/14  | ✓ primary |
| 5   | + strengthened prohibitions (gate failed) | 0.8269 | 0.7049 | 1.0000 | 4/5 ✗F003 | 3/3 | 9/14  | ✓ primary |
| 6   | gate met — MCP tools live | **0.9833** | 0.9672 | 1.0000 | **5/5** | 3/3 | 12/14 | ✓ primary |

¹ Severity-weighted (critical=4, high=2, medium=1, low=0.5); total GT weight = 30.5.
² Count-based evidence-traceability precision (computed, not stubbed). `count_fp = 0` for all runs.

Each row passed two internal consistency checks: `count_tp + count_fp + legit-unmatched + uncertain
== agent_finding_count`, and `Σ(matched severity weights) == weighted_tp`.

### Headline (v0.5)

**Run 6 (best config — MCP tools live, gate verified): F1 = 0.9833, recall = 0.9672, precision = 1.0,
5/5 critical, 3/3 FP traps, 12/14 matched.** GT F006 recovers at the **primary** pass once the v0.4
cache-key collision is removed. Post-tuning runs (2+3) mean F1 = 0.885, recall = 0.795.

The defining v0.5 finding is that **real precision = 1.0 for every run** (`count_fp = 0` throughout):
the precision judge never found an illegitimate unclaimed finding. The agent's "extra" findings
(beyond the 14-item GT) consistently cite verifiable artifacts — they are out-of-GT-scope, not
hallucinated. The v0.4 precision stub of 1.0 turns out to have been coincidentally correct; v0.5
substantiates it.

### Pre-registered predictions E1–E4

Locked in `design/scorer-v0.5.md` before any judge call; evaluated only after all 6 runs scored.

| # | Prediction | Verdict | Note |
|---|------------|:-------:|------|
| E1 | True F1 < v0.4 F1 for **all** runs | **DEVIATED** | Held for none-as-stated: R1/R2/R4 flat, R3/R5 down, R6 up. With `count_fp = 0` everywhere, precision adds no penalty; F1 moves are recall-driven, not precision-driven. The premise (real precision pulls F1 down) was falsified. |
| E2 | Run 6 > Run 3 F1 ordering survives | **MET** | 0.9833 > 0.9107. |
| E3 | Run 6 has the smallest precision drop | **DEVIATED** | All precision drops are 0 (precision = 1.0 everywhere). No differential to rank; the predicted mechanism is absent. |
| E4 | Run 1 has a larger precision drop than Run 3 | **DEVIATED** | Both drops are 0 — equal, not larger. Same root cause as E3. |

**Acceptance criterion (not a prediction):** *GT F006 in Run 6 matched via the primary pass.* **MET** —
`via_fallback = false`. This validates the cache-collision diagnosis; if F006 had only recovered via
the fallback pass, the cache theory would have been wrong. It did not — primary-pass recovery confirms
the stale-verdict collision was the cause.

**E1/E3/E4 share one root cause:** the precision judge returned zero illegitimate verdicts across all
six runs. The deviations are disclosed, not smoothed: the hypothesis that real precision would
penalise unclaimed findings did not survive contact with the data, because the agent's unclaimed
findings are evidence-grounded.

### Recall deltas vs v0.4 (weight-level)

The primary matching pass is algorithmically unchanged from v0.4 except for the cache key. Match-set
differences therefore come from (a) the F006 collision fix and (b) fresh judge verdicts replacing
v0.4's frozen cache on borderline pairs.

| Run | v0.4 wtp | v0.5 wtp | Δwtp | v0.4 matched | v0.5 matched |
|-----|---------:|---------:|-----:|-------------:|-------------:|
| 1 | 23.5 | 23.5 | 0.0  | 8  | 8  |
| 2 | 23.0 | 23.0 | 0.0  | 10 | 10 |
| 3 | 26.0 | 25.5 | −0.5 | 11 | 10 |
| 4 | 24.5 | 24.5 | 0.0  | 9  | 9  |
| 5 | 23.0 | 21.5 | −1.5 | 10 | 9  |
| 6 | 27.0 | 29.5 | +2.5 | 11 | 12 |

- **R6 +2.5:** F006 recovery (high, +2) plus one additional low-weight finding — the designed effect
  of the cache-key fix.
- **R3 −0.5, R5 −1.5:** small net losses, attributable to either v0.4 ID-cache cross-run collisions
  that spuriously credited a pair (now correctly declined under content-addressed keys) or to the
  documented `temperature=0` near-determinism flipping a borderline confidence-3/4 verdict. Either
  way it is not a methodology regression: no critical finding or FP-trap outcome changes. Per-finding
  verdicts are in `analysis/v05_rescoring/run{N}_score.json`.

### Adversarial precision calibration: is precision=1.0 a metric or a stub?

Across all six agent runs, `weighted_precision = 1.0` and `count_fp = 0`. A value that
never varies has no demonstrated discriminative power on its own — a computed 1.0 is
observationally indistinguishable from the v0.4 hardcoded stub it replaced. To
establish that the v0.5 precision pass is a live, discriminating metric rather than an
inert one, we ran a pre-registered adversarial calibration
(`design/scorer-v0.5-adversarial.md`, committed before the adversarial findings file
was authored).

**Method.** Run 6's real findings file (17 findings: 12 matched + 5 legitimately
unmatched) was used as the base, with recall held as a control. Six fabricated
findings were appended, graded into three tiers, each with a verdict predicted *before*
scoring:

- **Tier A — artifact-free conclusions (3):** malware/exfil/rootkit claims with empty
  evidence, no PID/path/IP/hash/tool-output cited. Predicted: caught as false positive.
- **Tier B — fabricated-but-cited (2):** internally coherent findings citing plausible
  but entirely invented specifics (a fake PID + unroutable IP; a fake hash + fake YARA
  match). Predicted: scored legitimate and passed through, because the judge is
  image-blind and cannot verify cited artifacts against the image.
- **Tier C — borderline (1):** a hedged injection claim citing a PID but no memory
  address or byte signature. Predicted: hedged to uncertain (dropped from denominator).

**Result — zero deviations from the pre-registration.**

| Metric | Pre-registered | Observed |
|---|---|---|
| weighted_recall (control) | 0.9672 (must hold) | 0.9672 ✓ |
| weighted_precision | 0.80 = 12/(12+3) | 0.80 ✓ |
| count_fp | 3 (Tier A) | 3 ✓ |
| count_legit_unmatched | 7 (5 real + 2 Tier-B) | 7 ✓ |
| count_uncertain | 1 (Tier C) | 1 ✓ |

Recall held exactly, confirming the injection did not disturb the match pass and the
run is valid. Every per-tier verdict matched its prediction: Tier A → `legitimate=false`
at confidence 5 (false positive); Tier B → `legitimate=true` at confidence 5 (dropped);
Tier C → confidence 3 (uncertain, dropped).

**What this establishes.**

1. **Precision is live, not stubbed.** The metric drops to 0.80 when findings assert
   conclusions with no traceable evidence. The 1.0 on the six real runs is therefore a
   *computed, discriminating* result — the real findings are evidence-grounded — not a
   carried-over stub.

2. **The metric catches for the right reason.** Tier A was flagged specifically on
   empty evidence ("no traceable artifact"), and the judge volunteered a domain-correct
   rationale on the exfiltration claim — that memory forensics tools do not directly
   measure data transfer volumes. The verdict reflects evidence-tracing, not surface
   pattern-matching on what "looks fake."

3. **The ceiling is characterized, not hidden.** Tier B passed through exactly as
   predicted: coherent fabrications with cited (but invented) specifics read as
   traceable, because the precision judge sees only the finding's self-reported
   evidence and cannot check a cited PID, IP, or hash against the memory image. This is
   the documented LLM-as-enricher failure mode — an internally coherent claim that
   collapses only against external ground truth the model does not possess (cf. Carrier,
   *DFIR+AI Primer: How to Combat Hallucinations*, 2026, on a model asserting a hostname
   it could not source). **The benchmark measures evidence *traceability*, not evidence
   *truth*** — and this run defines that boundary precisely.

4. **Two complementary detection layers.** The strict findings validator independently
   rejects all three Tier-A fabrications by structure (a CONFIRMED finding with empty
   `tool_attribution` fails strict validation) before the judge is invoked. The judge
   then catches the same class by evidence-tracing in permissive mode. Tier B passes
   both layers and is the residual that neither a structural schema check nor an
   image-blind LLM judge can catch. This mirrors the deterministic-check vs.
   judging-LLM distinction in the hallucination literature.

**The harden-it direction (future work, out of scope for this submission).** The
residual Tier-B class is closable only by a structurally different mechanism: a
deterministic query-for-item-existence pass that checks every cited PID / path / IP /
hash against the run's actual tool output or the image — Carrier's verification method
#1, distinct from the LLM-judge approach. This is recorded as the v-next direction; it
is not a prompt refinement but a different verification layer, and it is deliberately
not in the June 15 scope.

**Reproducibility.** The adversarial findings file, the score JSON, and the
freshly-generated judge verdicts are committed; the result reproduces from the cache
without an API key, identically to the six agent runs.

---

## Headline (v0.4)

Post-tuning runs (N=2, runs 2+3): **mean v0.4 score = 0.890 ± 0.030, recall = 0.803 ± 0.049** (recall is severity-weighted; critical=4, high=2, medium=1, low=0.5). All 5 critical findings identified in runs 1 and 3. Run 2 missed one critical finding (GT F005, PowerShell C2 shell with stealth flags) — determined to be a genuine agent gap corrected by the judge; v0.3 was over-crediting it via keyword overlap. See "Confidence-3 verdict investigation" below.

**Run 4 (MCP-enabled):** F1 = 0.8909, recall = 0.8033. All 5 critical findings identified, all 3 FP traps caught. E5 deviated (−0.03 from Run 3); E1–E3 all deviated — both MCP tools bypassed by the agent in favor of direct Python invocation. See "Run 4" section below for full E1–E6 disclosure.

**Run 5 (strengthened prohibitions, gate failed):** F1 = 0.8598, recall = 0.7541. 4/5 critical (missed GT F003 WMI lateral movement). All 3 FP traps caught. F01 (p.exe) matched at confidence=5 despite UNCONFIRMED status — judge credited content over classification. MCP gate not met; E1/E2/E3 untestable. See "Run 5" section and "Reframing note."

**Run 6 (gate met — first fair test of R5-E1/E2/E3):** F1 = 0.9391, recall = 0.8852. All 5 critical findings matched at confidence=5. All 3 FP traps caught. Both `mcp__hash_file` and `mcp__yara_scan` invoked — E1/E2/E3 all MET. F1 above pre-registered band (0.871–0.911); positive surprise: DLL profile (F013) and additional rundll32 (F014) now appear as standalone findings rather than consolidated into F01. See "Run 6" section for full E1–E6 evaluation.

---

## Run table (v0.4)

| Run | Config | v0.4 Score | Recall¹ | Critical (must-find) | FP traps | Negative assertions | Findings matched |
|-----|--------|------------:|-------:|---------------------:|---------:|--------------------:|-----------------:|
| 1   | Baseline CLAUDE.md | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2   | + `dlllist` + persistence check | 0.8598 | 0.7541 | 4/5 ✗F005 | 2/3 | 3/5 | 10/14 |
| 3   | + output schema pin | 0.9204 | 0.8525 | **5/5** | 3/3 | 3/5 | 11/14 |
| 4   | + MCP server (hash_file + yara_scan) | 0.8909 | 0.8033 | **5/5** | 3/3 | 3/5 | 9/14 |
| 5   | + strengthened prohibitions (gate² failed) | 0.8598 | 0.7541 | 4/5 ✗F003 | 3/3 | 4/5 | 10/14 |
| 6   | gate met — MCP tools live | **0.9391** | 0.8852 | **5/5** | 3/3 | 3/5 | 11/14 |

¹ Recall is severity-weighted (critical=4, high=2, medium=1, low=0.5) so it does not increase monotonically with raw matched count.  
² **Gate** = pre-run check confirming Claude Code had loaded the MCP server and could call the enrichment tools.

**Post-tuning mean (runs 2 + 3):** v0.4 score = 0.890, σ = 0.030 · Recall = 0.803, σ = 0.049

Run 4 is the MCP-enabled run scored against the same frozen v0.4 scorer. Run 3 is the MCP-disabled baseline for the A/B comparison.

Scored against `findings_post_correction.json` for all runs. Precision approximated at 1.0 under v0.4 (v0.5 scope — see metric note above). All scores produced by `scorer/scorer.py` v0.4 with `claude-sonnet-4-6` as judge, prompt hash `d6cfae8c...`, verdicts cached in `scorer_cache/judge_verdicts.json`.

## Methodology checklist + self-correction table (v0.4)

Produced by `scorer/checklist.py` and `scorer/self_correction.py`. `n/a` = source file absent for that run.

| Run | Checklist | Missing step | FP traps caught | Retractions | Additions |
|-----|----------:|--------------|----------------:|------------:|----------:|
| 1   | 8/9       | dlllist      | **3/3**         | 2           | 3         |
| 2   | 9/9       | —            | 2/3             | 2           | 4         |
| 3   | 9/9       | —            | **3/3**         | 0           | 0         |
| 4   | n/a       | —            | **3/3**         | 3           | 0         |
| 5   | 9/9       | —            | **3/3**         | 3           | 0         |
| 6   | 9/9       | —            | **3/3**         | 0           | 0         |

**Checklist:** run 1 missed `dlllist` (step added in run 2 CLAUDE.md); all subsequent runs achieve 9/9.
**FP traps:** run 2 missed FP002 (McAfee UpdaterUI) — the agent did not retract it during self-correction. All other runs caught all 3. Run 1's 3/3 reflects pre-correction retractions already in place before Phase 2 (the self-correction phase was not formally structured in run 1).
**Retractions/additions:** run 3 and run 6 show 0 retractions and 0 additions — the agent's pre-correction findings were already clean, requiring no Phase 2 changes. Runs 4 and 5 show 3 retractions each: the tightened evidence-attribution rules in the CLAUDE.md output schema drove the agent to downgrade findings that lacked direct tool attribution.

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

- **F008** (high): Full attack chain process tree — a stable miss through Run 5, recovered in Run 6 via the primary pass. In Runs 1–5 the agent described the chain narratively but did not produce a structured finding with the parent-child sequence as the primary subject.
- **F011** (low): spsql NTUSER.DAT in memory — missed in all six runs. No methodology step explicitly checks loaded user hives. The v0.3 "weak score-2 match" in run 3 (agent F07 via keyword overlap) was the false positive GT F011/F07 described in the design doc; v0.4 correctly does not credit it.

---

## Run 4 — MCP server integration (pre-registered expectations E1–E6)

Pre-registered in `design/mcp-server-v1.md` before Run 4 was executed. Results evaluated against frozen v0.4 scorer output.

**E1 — Agent invokes `hash_file` at least once:** DEVIATION. F01 contains `file_hash_sha256: "6f9d6ec7e163..."`, but the `tool_attribution` field lists only `vol ... windows.pslist --dump --pid 8260` and a direct Python yara call — no `mcp__hash_file` invocation and no hash tool of any kind. The sha256 was computed by some inline path (hashlib, sha256sum, or similar) and not attributed. The acceptance criterion was MCP tool invocation; presence of a sha256 in evidence does not distinguish the two paths, and the attribution evidence points to bypass.

**E2 — Agent invokes `yara_scan` at least once:** DEVIATION. This is the most substantive finding from Run 4. A YARA match is present in F01 (`Meterpreter_NamedPipe_Transport`, not one of the four rules in `yara_rules/srl-2018-operative.yar`). The tool_attribution is `python3 yara.compile('Meterpreter_NamedPipe_Transport').match('8260.p.exe.0x400000.dmp')` — a direct yara-python call, not `mcp__yara_scan`. The pre-registered language was explicit: "the invocation itself is what's verified." The agent did YARA work and surfaced useful evidence, but bypassed the MCP server entirely and used neither the registered tool nor the operative ruleset. No execution_log.json was produced, so no call-chain verification is possible. The MCP server was registered and verified reachable at design time; whether the agent saw it during Run 4 — or whether the CLAUDE.md `mcp__` naming was directive enough — is unresolved and is the right question for Run 5.

**E3 — At least one finding includes a sha256 from `hash_file`:** DEVIATION. Same finding as E1: sha256 is present in F01 evidence, but the source was not `mcp__hash_file`. E3 rested on "sha256 present in evidence" — that criterion was too weak. Both tools were bypassed; neither produced attributed output.

**E4 — Phase 2 does not retract a malware finding solely for lack of hash/YARA evidence:** MET. No malware-class finding was retracted. F01 survived self-correction with high confidence.

**E5 — Run 4 v0.4 score within ±0.02 of Run 3 (expected 0.900–0.940):** DEVIATION. Actual score = 0.8909, −0.0295 from Run 3's 0.9204. Recall gap: 0.8033 vs 0.8525 = −0.049. The gap is fully accounted for: Run 4 loses F012 (weight 1), F013 (weight 2), F014 (weight 0.5) relative to Run 3 and gains F006 (weight 2), for a net −1.5 weight / 30.5 total = −0.049 recall. The DLL-consolidation explanation covers F013 and F014 (agent merged DLL profile into F01 rather than producing standalone findings); F012 (procdump.exe in Dashlane directory) is a separate miss with no enrichment-related explanation. There is no unexplained residual: the arithmetic closes exactly. Note: the −0.131 recall figure in an earlier draft of this section was incorrect — it used Run 3's v0.3 recall (0.934) instead of v0.4 (0.8525).

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

**R5-E5 — Run 5 v0.4 score within ±0.02 of Run 4 (0.871–0.911):** DEVIATION DOWNWARD. Actual score = 0.8598 (−0.031 from Run 4's 0.8909, outside the band by 0.013). Recall = 0.7541 vs Run 4's 0.8033 = −0.049. GT F003 (WMI lateral movement, weight=4) missed — the agent described WMI execution but the judge declined to match it to the Run 5 WMI finding, likely due to the finding's UNCONFIRMED status or thin evidence framing. GT F013 (p.exe DLL profile, weight=2) also missed — collapsed into the UNCONFIRMED F01 finding. F01 itself matched GT F001 at confidence=5 despite being UNCONFIRMED: the judge correctly evaluated content over classification label, confirming that UNCONFIRMED status is transparent to the scorer.

**R5-E6 — No FP regression:** MET. All 3 FP traps retracted (F11, F12, F13 all status=RETRACTED). Phase 1 prohibitions did not affect FP detection.

**Run 5 findings summary:** 15 total — 8 CONFIRMED, 4 UNCONFIRMED (F01 malware, F07 lateral movement, F14 lateral movement, F15 credential access), 3 RETRACTED (FP traps). Final score: F1 = 0.8598, recall = 0.7541, 4/5 critical, 10/14 matched.

**Overall:** E4, E6 met. E1, E2, E3 not testable (gate failed). E5 deviated downward (−0.031 from Run 4, outside band). Run 5's primary demonstrated value: Phase 2 audit clause behavior under tool absence — agent correctly declined to CONFIRM malware findings without MCP evidence. Downward F1 deviation is partly attributable to missing GT F003 (WMI), which appeared in Run 6 when the investigation was cleaner, and to DLL evidence consolidation into F01 rather than standalone F013.

---

## Run 6 — Gate met; R5-E1/E2/E3 evaluated

Gate verified and committed at `41d7c71` (`cases/srl-2018/run6_analysis/mcp_verification.txt`). Both `mcp__hash_file` and `mcp__yara_scan` confirmed live before execution. The CLAUDE.md prohibitions are unchanged from Run 5; the only change is the server being actually available.

**R6-E1 — Agent calls `mcp__hash_file` at least once:** MET. Tool invoked twice — `p.exe` process dump (seq 17) and `procdump.exe` data dump (seq 19). Both logged in `execution_log.json` with `tool: "mcp__sift-bench-enrichment__hash_file"`. Summary field confirms `mcp__hash_file_count: 2`.

**R6-E2 — Agent calls `mcp__yara_scan` at least once:** MET. Tool invoked twice — scanning `p.exe` dump (seq 18) and `procdump.exe` dump (seq 20), both against `yara_rules/srl-2018-operative.yar`. Both logged with `tool: "mcp__sift-bench-enrichment__yara_scan"`. Summary confirms `mcp__yara_scan_count: 2`. Both scans returned 0 matches. This outcome motivated a post-Run 6 rule diagnosis (see `design/yara-rules-v2.md`): the operative ruleset's Rule 4 uses ASCII-only string matching, which does not fire against UTF-16LE command-line arguments stored in memory; and the Meterpreter DLL-pattern rules target plaintext string constants absent from a packed payload. Two novel rules were written to address these gaps (`yara_rules/srl-2018-novel.yar`). Validation against the Run 6 extracted artifacts confirmed a pre-registered match: `SIFT_Procdump_Sysinternals_Marker` fired against the procdump.exe DataSectionObject (SHA256: `8b87ad36...`); result committed at `cases/srl-2018/run6_analysis/yara_novel_validation.txt`.

**R6-E3 — At least one finding includes `file_hash_sha256` from `mcp__hash_file`:** MET. F01 (p.exe) contains `file_hash_sha256: "6f9d6ec7e1634f80de9fa5c0792806f7d63960c799be826f296d52af94a06fc0"` with `mcp__hash_file` in `tool_attribution`. F10 (procdump.exe) contains `file_hash_sha256: "8b87ad368f48a2414834cedafa3caafb9b07d8710699cb6df105e5a8e2616821"`. Both hashes are attributable to registered MCP invocations — closing the ambiguity that made the Run 4 E3 criterion insufficient.

**R6-E4 — Phase 2 does not retract a malware finding solely for lack of hash/YARA evidence:** MET. F01 (p.exe) and F10 (procdump.exe) remained CONFIRMED with `confidence=high` after self-correction. Phase 2 found no issues — pre- and post-correction findings files are structurally identical.

**R6-E5 — Run 6 v0.4 score within ±0.02 of Run 4 baseline (0.871–0.911):** DEVIATION UPWARD. Actual score = 0.9391 (recall = 0.8852), above band by +0.028. Breakdown vs Run 4 (weighted_tp = 24.5):
- Run 6 recovers GT F003 (WMI lateral execution, weight=4): CONFIRMED framing in Run 6 vs absent in Run 5; clean evidence trail enabled judge match at confidence=5.
- Run 6 recovers GT F013 (p.exe DLL profile, weight=2): F09 produced as standalone finding rather than merged into F01.
- Run 6 loses GT F006 (six rundll32 from PS 5848, weight=2): under v0.4 scoring, finding F06 was present in Run 6 with correct evidence but was not credited. **The original attribution here (K=3 pre-filter keyword competition) was wrong — see "F006 correction" below.** The true cause was a v0.4 cache-key collision; under v0.5 content-addressed keys, F006 matches Run 6 at the primary pass.
- Net: +6 − 2 = +4 weight over Run 4 → recall 0.8852 vs 0.8033 (+0.082). F1 rise from 0.8909 to 0.9391 reflects cleaner CONFIRMED classification enabling better judge matching for all GT items. (Under v0.5, with the F006 collision fixed, Run 6 recall rises further to 0.9672 and F1 to 0.9833.)

**R6-E6 — No FP regression:** MET. All 3 FP traps retracted (F15 Outlook dtrR, F16 McAfee UpdaterUI, F17 CLR heap). MCP invocations and CONFIRMED status changes did not affect false-positive detection.

**Run 6 findings summary:** 17 total — 14 CONFIRMED, 0 UNCONFIRMED, 3 RETRACTED (FP traps). Final score: F1 = 0.9391, recall = 0.8852, 5/5 critical, 11/14 matched. GT misses: F006 (scoring artifact; finding present), F011 (spsql NTUSER.DAT; stable miss across all runs), F012 (procdump.exe; stable miss shared with Runs 4/5).

**Core result:** All three pre-registered MCP routing expectations (E1/E2/E3) were met in Run 6. The strengthened CLAUDE.md prohibitions, combined with the server being available, produced the intended routing behavior: agent invoked registered MCP tools rather than inline equivalents. v1 acceptance criteria are met. The F1 above band (0.9391 > 0.911) is a positive deviation attributable to cleaner finding classification enabling GT F003/F013 recovery; it does not represent a methodology change.

**Run 6 baseline:** Run 4 (0.8909 F1, 0.8033 recall) is the comparison baseline — same CLAUDE.md prohibitions as Run 5, same frozen v0.4 scorer, same ground truth. Run 3 (0.9204) is not the baseline.

---

## Unstable behaviors (noise) — v0.4

| Behavior | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Run 6 |
|----------|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
| F005 (PowerShell stealth shell) | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| F006 (six rundll32 from PS 5848) | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ → ✓³ |
| F013 (p.exe DLL profile) | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ |
| McAfee UpdaterUI FP retraction (FP002) | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| Total findings produced | 19 | 14 | 19 | 15 | 15 | 17 |

**F006 across runs — corrected.** An earlier draft of this section claimed F006 and F013 were
anti-correlated and attributed Run 6's F006 miss to the K=3 keyword pre-filter ("rundll32" terms
consumed by a DLL-heavy candidate pool). **This was verified incorrect — see "F006 correction"
below.** Run 6's agent finding F06 ranked 1st in the pre-filter (score=8, well inside K=3); the miss
was a v0.4 cache-key collision, not pre-filter competition. Under v0.5 (content-addressed keys) F006
matches Run 6 at the primary pass. Run 3's F006 miss is the genuinely different case: a real agent gap
(no finding describing the six rundll32 instances), correctly reflected by the pre-filter and not
recovered by the v0.5 fallback either. The two misses are distinct mechanisms and must not be
conflated.

**F013 pattern:** missed in Runs 1, 4, 5 (DLL evidence merged into F01); present in Runs 2, 3, 6 (produced as standalone F09). The MCP enrichment requirement may have prompted the agent to produce a more structured DLL-profile finding rather than embedding it in the malware finding.

**F005 recovered in Runs 4–6** after the single miss in Run 2 — consistent with methodology improvements (explicit `dlllist` and persistence-check instructions) making the C2 shell observation more salient.

³ Run 6 F006 shows ✗ under v0.4 and ✓ under v0.5 — the v0.4 ✗ was a cache-key collision, not an agent miss (see "F006 correction" immediately below).

---

## F006 correction (Run 6 misdiagnosis)

The committed v0.4 RESULTS.md attributed Run 6's GT F006 miss to the **K=3 keyword pre-filter** —
claiming agent finding F06 was crowded out of the top-3 candidate pool by DLL-heavy findings. **This
is verified incorrect.** A fresh pre-filter simulation against Run 6's findings places agent F06 at
**rank 1, score 8** — comfortably inside K=3. The judge *was* asked to evaluate the F006 pair.

The real cause was a **cache-key collision** in v0.4. The v0.4 key was ID-based
(`sha256("F006|F06|model|prompt_hash")`). Run 3 had been scored before Run 6 against the shared
persistent cache, and Run 3's F06 ("p.exe DLL inventory") had populated exactly that key with a
`match=False` verdict. When Run 6's F06 ("Six rundll32.exe instances from PowerShell C2 shell")
hashed to the same ID-based key, the scorer returned Run 3's stale verdict **without ever calling the
judge on Run 6's actual content**. The collision was an artifact of scoring order against a shared
cache: scoring the runs in the opposite order, or with a fresh cache per run, would have produced a
different (or no) collision.

**Two distinct F006 mechanisms, now documented separately:**

- **Run 3 — genuine agent gap.** Run 3's agent did not produce a finding describing the six
  short-lived rundll32 instances. The pre-filter correctly surfaced no matching top-3 candidate. F006
  is a true miss in Run 3, and the v0.5 per-pair fallback did **not** recover it (consistent with the
  design doc's note that the fallback has no demonstrated recovery on this dataset).
- **Run 6 — cache-key collision.** The agent produced the correct finding (rank 1); only the stale
  cached verdict suppressed it. v0.5's content-addressed keys (`sha256` over finding *content*, with
  `match`/`fallback`/`precision` type prefixes) eliminate the collision. On re-scoring, GT F006
  matches Run 6 at the **primary** pass (`via_fallback = false`, confidence 5) — the pre-registered
  acceptance criterion for the cache redesign, MET.

This correction lands in the same commit as the v0.5 numbers, per the `design/scorer-v0.5.md`
pre-registration.

---

## Tuning impact (v0.3 scoring, for reference)

Two methodology additions to `CLAUDE.md` between runs 1 and 2:

1. **Step 8:** `windows.dlllist` on attacker-controlled PIDs — DLL patterns to report (network/crypto stacks, post-execution load timestamps, AMSI/unnamed DLLs).
2. **Step 9:** `windows.registry.printkey` on Run/RunOnce keys + `windows.svcscan`, with explicit instruction to state absence as a negative finding.

Under v0.3 scoring: Run 1 → Run 2 was +0.105 F1. Under v0.4, the same methodology change produces +0.0 F1 (run 2 is actually lower than run 1 due to the F005 false credit being removed). The real tuning impact is better measured by findings recovered — F009, F013, F014, F012 all appear in run 2 for the first time — but F005 keyword credit was masking a genuine miss in run 2.

---

## Run table (v0.3, historical)

| Run | Config | v0.3 Score | Recall | Critical (must-find) | FP traps | Negative assertions | Findings matched |
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

**v0.4 → v0.5: real precision, per-pair fallback, content-addressed cache keys.** Three changes,
pre-registered in `design/scorer-v0.5.md`. (1) *Real precision* — the v0.4 precision stub (hardcoded
1.0) is replaced by an evidence-traceability judge that asks, per unclaimed agent finding, whether it
cites verifiable artifacts; `precision = count_tp / (count_tp + count_fp)`. On this dataset
`count_fp = 0` for all runs, so precision computes to 1.0 — the stub's value, now substantiated. (2)
*Per-pair fallback* — unmatched GT findings get a second judge pass over all unclaimed agent findings;
no recovery on the current 6 runs (insurance for future cases). (3) *Content-addressed cache keys* —
keys hash finding *content* (`sha256(json.dumps(finding, sort_keys=True))`) with `match`/`fallback`/
`precision` type prefixes, replacing the v0.4 ID-based keys that caused the Run 6 F006 cross-run
collision. All v0.4 entries are invalidated; v0.5's first pass is a 100% cache-miss regeneration,
re-committed for key-free reproduction.

---

## Scorer methodology (v0.4)

1. **Keyword pre-filter:** for each GT finding, score all unclaimed agent findings by keyword + title-word overlap. Drop candidates with score=0; take top-3 by score, tiebroken by agent ID lexicographically.
2. **LLM-as-judge gate:** call `claude-sonnet-4-6` on each candidate in order. First candidate returning `match=True, confidence ≥ 4` is credited; lower-confidence verdicts are logged as warnings.
3. **False-positive trap verification:** structured anchor matching (process name + PID) — unchanged from v0.3, judge not used here.
4. **Negative assertion verification:** keyword matching on absence claims — unchanged from v0.3.
5. **Scoring:** weighted TP/FN from GT severity weights. Precision approximated at 1.0 under v0.4; v0.5 implements evidence-traceability precision via LLM judge.

---

## Known limitations

- **v0.4 precision approximation.** Precision is approximated at 1.0 under v0.4; v0.4 scores are recall-weighted benchmark scores, not true F1. Scorer v0.5 (implemented; pending re-scoring) adds evidence-traceability precision.
- **K=3 pre-filter ceiling.** If the correct agent finding ranks below 3rd by keyword overlap, the judge never sees it. This remains a genuine architectural constraint (Run 3 GT F006 is a real agent gap the pre-filter cannot rescue). Note: Run 6 GT F006 was **previously misattributed** to this ceiling — it was actually a v0.4 cache-key collision (agent F06 ranked 1st). See "F006 correction."
- **N=2 post-tuning runs, single case.** Sufficient to characterize agent behavior on this image; generalization to other cases is a stretch goal. N=2 gives σ = 0.030 for the post-tuning mean.
- **Near-determinism caveat.** `temperature=0` is near-deterministic, not bit-identical at the model level. The committed cache makes *reruns* bit-identical; first scoring of a new pair is subject to small floating-point variation in inference.

---

## Reproducing

```bash
# Score best run from committed cache — no API key needed, bit-identical output
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json

# Score an earlier run (same cache; all verdicts committed)
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run3_analysis/findings_post_correction.json

# Run unit tests (94 tests; no memory image or API key needed)
python -m unittest discover -s tests
```

Cache file `scorer_cache/judge_verdicts.json` is committed to the repo (now holding the v0.5
content-addressed verdicts — match, fallback, and precision). A reviewer without an API key can rerun
all scoring passes and get bit-identical output. Scoring a findings file not already in the cache
requires `ANTHROPIC_API_KEY`. Per-run v0.5 score JSONs are in `analysis/v05_rescoring/`, and the
pre-registered prediction evaluation (E1–E4) is in `analysis/v05_rescoring/predictions_eval.md`.
