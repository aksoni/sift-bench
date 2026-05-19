# SIFT-Bench Results

**Benchmark:** SANS FOR508 Stark Research Labs, case SRL-2018, base-rd01 memory image (Windows 10 x64 Build 16299, captured 2018-09-06T18:57:17Z).

**Ground truth:** v1.1 — 14 findings (5 critical must-find, 3 high, 3 medium, 3 low), 3 false-positive traps, 5 negative assertions. Severity weights: critical=4, high=2, medium=1, low=0.5.

**Current scorer:** v0.4 — LLM-as-judge match gating. See "Scorer evolution" below. v0.3 numbers retained for comparison.

---

## Headline (v0.4)

Post-tuning runs (N=2): **mean weighted F1 = 0.890 ± 0.030, recall = 0.803 ± 0.049**. All 5 critical findings identified in runs 1 and 3. Run 2 missed one critical finding (GT F005, PowerShell C2 shell with stealth flags) — determined to be a genuine agent gap corrected by the judge; v0.3 was over-crediting it via keyword overlap. See "Confidence-3 verdict investigation" below.

---

## Run table (v0.4)

| Run | Config | Weighted F1 | Recall | Critical (must-find) | FP traps | Negative assertions | Findings matched |
|-----|--------|------------:|-------:|---------------------:|---------:|--------------------:|-----------------:|
| 1   | Baseline CLAUDE.md | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2   | + `dlllist` + persistence check | 0.8598 | 0.7541 | 4/5 ✗F005 | 2/3 | 3/5 | 10/14 |
| 3   | + output schema pin | 0.9204 | 0.8525 | **5/5** | 3/3 | 3/5 | 11/14 |

**Post-tuning mean (runs 2 + 3):** F1 = 0.890, σ = 0.030 · Recall = 0.803, σ = 0.049

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

- **F008** (high): Full attack chain process tree — missed in all three runs. The agent describes the chain narratively but does not produce a structured finding with the parent-child sequence as the primary subject.
- **F011** (low): spsql NTUSER.DAT in memory — missed in all three runs. No methodology step explicitly checks loaded user hives. The v0.3 "weak score-2 match" in run 3 (agent F07 via keyword overlap) was the false positive GT F011/F07 described in the design doc; v0.4 correctly does not credit it.

---

## Unstable behaviors (noise) — v0.4

| Behavior | Run 1 | Run 2 | Run 3 |
|----------|:-----:|:-----:|:-----:|
| F005 (PowerShell stealth shell) | ✓ | ✗ | ✓ |
| F006 (six rundll32 from PS 5848) | ✓ | ✓ | ✗ |
| F013 (p.exe DLL profile) | ✗ | ✓ | ✓ |
| McAfee UpdaterUI FP retraction (FP002) | ✓ | ✗ | ✓ |
| Total findings produced | 19 | 14 | 19 |

F013 is now stable in runs 2 and 3 — the v0.3 keyword-matcher instability (credited in runs 2–3, missed in run 1) has been replaced by consistent judge verdicts. Run 1 misses F013 because the agent's run 1 output did not include a DLL-profile finding, not because of matcher fragility.

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
