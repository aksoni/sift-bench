# Scorer v0.5 Design — Real Precision + Cache Key Correctness + Per-Pair Fallback

**Status:** Pre-registered design. Committed before any code changes.
**Author:** SIFT-Bench project
**Date:** 2026-05-21
**Supersedes:** Scorer v0.4 (weighted F1 with precision stub)

---

## Problem Statement

Scorer v0.4 has two known limitations.

### 1. Precision stub

`weighted_precision` is hardcoded to `1.0`, so `weighted_f1 ≈ weighted_recall`. Unclaimed agent
findings — hallucinated or unsupported claims — go completely unpenalized.

### 2. GT F006 misses — two distinct mechanisms across runs

**Run 3 — genuine pre-filter ceiling:** Run 3's agent did not produce a finding clearly describing
the six short-lived rundll32.exe instances from PS 5848. The top keyword-matching candidates were
PowerShell C2 shell findings. Run 3's F06 ("p.exe DLL inventory") ranked 4th (score=2), below the
K=3 cutoff. No top-3 candidate described the correct observation. This is a genuine agent gap,
correctly reflected by the scorer's pre-filter.

**Run 6 — cache key collision:** Run 6's agent *did* produce the correct finding: agent F06 = "Six
rundll32.exe instances spawned by PowerShell C2 shell (PID 5848)" — which ranked **1st** in the
pre-filter (score=8, well within K=3). `judge_pair(GT_F006, run6_F06)` was called, but the cache
key is ID-based: `sha256("F006|F06|model|prompt_hash")`. This key had a hit from Run 3's earlier
scoring, where Run 3's F06 was "p.exe DLL inventory confirms active C2 implant" — a completely
different finding. The stale verdict (`match=False, confidence=5, reasoning: "agent finding is about
p.exe DLL inventory"`) was returned from cache without an API call. Run 6's actual F06 content was
never evaluated by the judge.

The collision manifested because Run 3 was scored before Run 6 against a shared persistent cache.
If the runs had been scored in the opposite order the stale verdict would have pointed the other
way, and if each run had been scored against a fresh cache no collision would have occurred at all.
This ordering dependency is a property of the scoring history, not of the scorer alone.

**RESULTS.md misdiagnosis:** Lines 182 and 205 of the committed RESULTS.md attribute Run 6's F006
miss to K=3 keyword competition ("rundll32 terms consumed by the DLL-heavy candidate pool"). This
is verified incorrect. A fresh pre-filter simulation against run6_reports/findings.json shows agent
F06 at rank 1 / score=8. The true cause is the cache collision. RESULTS.md is corrected in the
same commit as v0.5 results with an explicit disclosure.

---

## Fixes

### Fix 1: Real precision via LLM-as-judge

For each unclaimed agent finding (every finding not claimed by the primary or fallback pass), ask a
judge whether the finding is **legitimate** — meaning a DFIR analyst could trace the claim to
specific, citable tool output.

**Three-bucket model:**

| Bucket | Definition | Precision treatment |
|--------|------------|---------------------|
| **TP (matched)** | Agent finding claimed by a GT match | Numerator and denominator |
| **FP (illegitimate)** | Unclaimed, judge says unsupported by citable evidence (confidence ≥ 4) | Denominator only |
| **Legit-unmatched** | Unclaimed, judge says evidence-supported but outside GT scope | Dropped from denominator |
| **Uncertain** | Unclaimed, judge confidence < 4 | Dropped from denominator |

**Formula:** `precision = count_tp / (count_tp + count_fp)`

**Asymmetry disclosure:** Precision is count-based (unit weight per agent finding); recall remains
severity-weighted (critical=4, high=2, medium=1, low=0.5). The harmonic mean is mathematically
valid (both in [0,1]) but produces a hybrid F1 that does not correspond to a single coherent
weighting scheme. Every report output and any document citing F1 must carry this caveat.

**`adjudicable == 0` edge case:** If `count_tp + count_fp == 0`, precision defaults to `1.0`.
Cannot occur for runs 1–6 but documented for completeness.

### Fix 2: Content-addressed cache keys (primary fix for Run 6 F006)

All cache key functions are rewritten to hash finding *content* via
`sha256(json.dumps(finding, sort_keys=True))` rather than IDs. This eliminates cross-run key
collisions. Every `(gt_finding, agent_finding)` pair is keyed by its actual content.

**Consequence:** All v0.4 cache entries are invalidated. Cache miss rate is 100% on the first v0.5
pass. All 6 runs must be re-fetched via API. This is the binding time and cost constraint against
the June 7 stop rule.

**Key functions:**

```python
def make_cache_key(gt_finding, agent_finding, model_snapshot, prompt_template) -> str:
    gt_hash = sha256(json.dumps(gt_finding,    sort_keys=True))
    af_hash = sha256(json.dumps(agent_finding, sort_keys=True))
    ph      = sha256(prompt_template)
    return sha256(f"match_v0.5|{gt_hash}|{af_hash}|{model_snapshot}|{ph}")

def make_precision_cache_key(agent_finding, model_snapshot, prompt_template) -> str:
    af_hash = sha256(json.dumps(agent_finding, sort_keys=True))
    ph      = sha256(prompt_template)
    return sha256(f"precision_v0.5|{af_hash}|{model_snapshot}|{ph}")

def make_fallback_cache_key(gt_finding, agent_finding, model_snapshot, prompt_template) -> str:
    gt_hash = sha256(json.dumps(gt_finding,    sort_keys=True))
    af_hash = sha256(json.dumps(agent_finding, sort_keys=True))
    ph      = sha256(prompt_template)
    return sha256(f"fallback_v0.5|{gt_hash}|{af_hash}|{model_snapshot}|{ph}")
```

Type prefixes (`match_v0.5`, `precision_v0.5`, `fallback_v0.5`) prevent collisions between verdict
types stored in the same cache.

**`json.dumps` stability note:** `sort_keys=True` stabilizes dict key ordering. If any finding
field carries an order-unstable list whose semantics are order-independent (e.g., a `tags` list
emitted in varying order), two semantically-identical findings will hash differently and silently
miss the cache — a cache-efficiency leak, not a correctness bug. Agent finding schemas should be
checked for unordered list fields before the key is treated as canonical.

### Fix 3: Per-pair fallback (defense-in-depth for pre-filter ceiling)

After the primary pass, any GT finding still in `findings_missed` enters a fallback pass. The
fallback iterates every unclaimed agent finding and calls `judge_fallback_pair(gt, af)` per pair.

**Motivation:** Guards against genuine pre-filter ceiling cases — where a correct agent finding
ranks below K=3, or where all high-scoring candidates are already claimed. Run 3's F006 miss
illustrates the pattern (agent's top-3 candidates were all non-rundll32 observations). **The
fallback has no demonstrated recovery in the current 6-run dataset — it is insurance for future
cases.**

**Why per-pair, not batch:** A batch prompt reintroduces position bias, which motivated v0.4's
pairwise design. The fallback uses the same one-(gt, agent)-pair-at-a-time structure.

**One match per GT finding:** The fallback breaks after the first `confidence >= 4` match per
unmatched GT item.

---

## Scoring Algorithm (v0.5)

```
PRIMARY PASS (unchanged from v0.4):
  For each GT finding (severity-weight desc):
    Pre-filter to top-3 by keyword/title overlap
    For each of top-3: judge_pair(gt, af)   <- now content-addressed key
    If match (confidence >= 4): claim af, record TP

DISJOINT COVERAGE ASSERTION:
  Assert: matched_gt_ids ∩ missed_gt_ids == ∅
  Assert: matched_gt_ids ∪ missed_gt_ids == all_gt_ids

FALLBACK PASS:
  For each unmatched GT finding:
    For each unclaimed agent finding:
      judge_fallback_pair(gt, af)
      If match (confidence >= 4): claim af, move GT to matched, break

PRECISION PASS:
  count_tp = len(findings_matched)
  For each unclaimed agent finding:
    judge_precision(af)
    If confidence >= 4: FP or legit-unmatched
    Else: uncertain
  precision = count_tp / (count_tp + count_fp)

METRICS:
  weighted_recall    = weighted_tp / (weighted_tp + weighted_fn)   [severity-weighted]
  weighted_precision = count_tp / (count_tp + count_fp)            [count-based]
  weighted_f1        = 2 * P * R / (P + R)                         [hybrid — see disclosure]
```

---

## Judge Prompts

### `judge_v0.5_precision.txt`

Frame: given an agent finding, ask whether the finding cites specific identifiable artifacts — a
PID, file path, hex offset, network tuple, or registry key — that a DFIR analyst could verify
against tool output. `legitimate=true` if citable; `legitimate=false` if unsupported or
inconsistent with tool output.

**Verdict schema:** `{"legitimate": bool, "confidence": 1-5, "reasoning": "..."}`

### `judge_v0.5_fallback.txt`

Same structure and verdict schema as `judge_v0.4.txt`. Different framing: "the following GT finding
had no strong match in the primary evaluation pass — check whether this agent finding describes the
same forensic observation, even if described in different terms or at a different level of
specificity."

**Verdict schema:** `{"match": bool, "confidence": 1-5, "reasoning": "..."}`

---

## Pre-registered Predictions

Locked before any judge call.

1. **True F1 < v0.4 F1 for all runs** [blind]
2. **Run 6 > Run 3 F1 ordering survives precision correction** [blind]
3. **Run 6 has the smallest precision drop** [inspection-informed, weak — Run 6's agent cited
   MCP-attributed evidence extensively, suggesting grounded claims; note this rationale bears on
   *claimed* findings, not the unclaimed ones precision actually evaluates]
4. **Run 1 has a larger precision drop than Run 3** [blind — Run 1 matched 8/14 leaving 11
   unclaimed agent findings; Run 3 matched 11/14 leaving 8 unclaimed; assuming the fallback claims
   no additional findings, which is expected given no demonstrated recovery in current data]

**Acceptance criterion** (not a prediction — if this fails, the cache redesign has failed and
results must not be committed until investigated):

GT F006 ("Six short-lived rundll32.exe instances from PowerShell C2 shell") in Run 6 appears in
`findings_matched` after v0.5 re-scoring **via the primary pass** (`"via_fallback"` absent or
False). Primary-pass recovery validates the cache collision diagnosis. If F006 only recovers via
fallback, the cache theory was wrong — the pre-filter or a different mechanism was the true cause —
and this outcome must be disclosed in RESULTS.md, not smoothed over.

---

## RESULTS.md Correction Required

The following committed claims are verified incorrect for Run 6 and must be corrected in the same
commit as v0.5 results:

- **Line 182:** "K=3 pre-filter likely excluded F06 from candidates for GT F006 (keyword
  competition with higher-ranked candidates)"
- **Lines 200–205:** The anti-correlation table note attributing F006 misses in Runs 3 and 6 to
  the same K=3 keyword-competition mechanism

**Correction:** Run 3's F006 miss is a genuine pre-filter/agent gap — the agent did not produce a
correct observation; the pre-filter correctly reflected the available content. Run 6's F006 miss is
a cache key collision — agent F06 ranked 1st (score=8) and was passed to `judge_pair`, but the
cache returned Run 3's stale verdict before any API call. The collision manifested because Run 3
was scored before Run 6 against a shared persistent cache; scoring in the opposite order would have
produced a different stale verdict, and a fresh cache per run would have avoided it entirely. These
are different mechanisms and must be documented separately.

---

## Cache Invalidation Contract

`scorer_cache/judge_verdicts.json` is content-addressed (see Fix 2), so most
changes do not require a manual wipe — they simply produce different keys and
miss the cache, leaving orphan entries that are inert but harmless. A few
changes require deliberate action.

**Safe to leave orphans (no manual wipe required):**

- **Prompt edit.** A new `sha256(prompt_template)` appears in the key suffix, so
  every pair re-fetches. Old entries are unreachable but not wrong.
- **Finding content edit in a re-run.** Content hash changes; new key, cache
  miss, re-fetch. Old entry is unreachable.
- **Model snapshot bump** (e.g., `claude-sonnet-4-6` → `claude-sonnet-4-7`).
  Model snapshot ID is in the key; full miss on first re-score. Same as a
  prompt edit in effect.

**Requires a manual wipe (delete `scorer_cache/judge_verdicts.json`):**

- **Cache value schema change** (e.g., adding a new field to `JudgeVerdict` that
  downstream code reads, or changing the meaning of an existing field). Existing
  entries are *readable* but semantically stale; new fields will read as
  missing. A defensive `kind` tag on entry values (see item 8 in the project
  task list) reduces this risk to the case of an actual semantic change.
- **Verdict logic change in a way that should not be cached forward** — e.g.,
  fixing a judge prompt bug where past `match=True` verdicts were systematically
  wrong. Even though the prompt hash differs, if reviewers want to assert that
  the new verdicts are derived fresh from a clean state, a wipe is required.
- **Cache key function change.** If `make_cache_key` itself is edited (algorithm
  change, prefix string change, etc.), every entry becomes unreachable. Leaving
  them is harmless but adds dead bytes; a wipe is recommended for hygiene.

**Never required:**

- **Adding a new run.** Content-addressed keys partition by finding content, so
  Run 7's verdicts cannot collide with Runs 1–6.
- **Re-ordering which runs get scored.** This was the v0.4 → v0.5 fix; ordering
  cannot affect verdicts under content-addressed keys.

**Audit before any wipe:** committing the cache means external reviewers can
re-derive bit-identical scores without an API key. Wiping it forces a full
re-fetch on the next run, which costs API time and (for them) money. Prefer
content-addressed orphaning over wipes whenever the change is correctness-
preserving.

---

## Stop Rule

v0.5 complete and all 6 runs re-scored before **June 7, 2026**. If missed, v0.4 stays canonical
and v0.5 ships as design-doc-only evidence of methodology awareness. Full cache regeneration (100%
miss rate on first pass) is the binding constraint near the deadline.

---

## Files Changed

| File | Type | Change |
|------|------|--------|
| `design/scorer-v0.5.md` | new | This document — committed before any code |
| `scorer/judge_cache.py` | modify | Content-addressed key functions, `PrecisionVerdict`, `get_precision`/`put_precision` |
| `scorer/judge.py` | modify | `judge_pair` caller update; add `judge_precision`, `judge_fallback_pair` |
| `scorer/prompts/judge_v0.5_precision.txt` | new | Precision prompt |
| `scorer/prompts/judge_v0.5_fallback.txt` | new | Fallback match prompt |
| `scorer/scorer.py` | modify | Fallback pass, precision pass, disjoint assertion, replace precision stub, `print_report` |
| `tests/validate_judge.py` | modify | Precision + fallback regression cases + collision guard test |
| `RESULTS.md` | modify | Correct Run 6 F006 misdiagnosis; separate Run 3 and Run 6 mechanisms |

---

## Verification Checklist

1. `python tests/test_scoring_additions.py` — 20 existing tests pass (checklist/self-correction
   untouched)
2. Score any run twice after full regeneration — second pass: zero new cache entries, bit-identical
   output (validates determinism; first pass necessarily misses all v0.4 entries by construction)
3. Score Run 6 — GT F006 in `findings_matched` with `"via_fallback"` absent or False
   (primary-pass recovery validates cache collision theory)
4. Score all 6 runs — `weighted_precision < 1.0` for at least some runs
5. `python tests/validate_judge.py` — locked verdicts pass; collision guard test passes (two
   synthetic findings sharing the same `id` field but different content produce distinct cache key
   digests)
6. Evaluate all 4 predictions; document outcomes including any moving opposite to pre-registered
   direction
7. Commit RESULTS.md correction in same commit as v0.5 results — not as a separate cleanup

---

*Pre-registered design committed before any v0.5 code. Predictions locked as of commit timestamp.*
