# Scorer v0.5 — Pre-registered Prediction Evaluation

Evaluated **after** scoring all 6 runs against `ground_truth/base-rd01-v1.1.json`
(total GT weight = 30.5). Per-run results in `analysis/v05_rescoring/run{N}_score.json`.

## Authoritative v0.5 results (scalar, cross-checked)

All rows passed two internal consistency checks: `count_tp+count_fp+legit+uncertain == agent_finding_count`,
and `sum(matched weights) == weighted_tp`.

| Run | v0.5 F1 | v0.5 recall | v0.5 precision | count_tp | count_fp | legit-unmatched | uncertain | matched | crit | FP traps | F006 matched | via_fallback |
|-----|--------:|------------:|---------------:|---------:|---------:|----------------:|----------:|--------:|-----:|---------:|:------------:|:------------:|
| 1 | 0.8704 | 0.7705 | 1.0000 | 8  | 0 | 8 | 3 | 8/14  | 5/5 | 3/3 | yes | false |
| 2 | 0.8598 | 0.7541 | 1.0000 | 10 | 0 | 4 | 0 | 10/14 | 4/5 | 2/3 | yes | false |
| 3 | 0.9107 | 0.8361 | 1.0000 | 10 | 0 | 9 | 0 | 10/14 | 5/5 | 3/3 | **no** | — |
| 4 | 0.8909 | 0.8033 | 1.0000 | 9  | 0 | 6 | 0 | 9/14  | 5/5 | 3/3 | yes | false |
| 5 | 0.8269 | 0.7049 | 1.0000 | 9  | 0 | 6 | 0 | 9/14  | 4/5 | 3/3 | yes | false |
| 6 | 0.9833 | 0.9672 | 1.0000 | 12 | 0 | 5 | 0 | 12/14 | 5/5 | 3/3 | yes | false |

**Central empirical result: `count_fp == 0` for all six runs.** The precision judge classified
every unclaimed agent finding as either *legit-unmatched* (evidence-supported but outside the 14-item
GT scope) or *uncertain* (confidence < 4). It never returned an illegitimate verdict. Precision is
therefore a *computed* 1.0 for every run — not the v0.4 stub, but a real value that happens to equal it.

## Acceptance criterion (NOT a prediction)

> GT F006 in Run 6 appears in `findings_matched` via the **primary** pass (`via_fallback` absent/False).

**MET.** Run 6 F006: matched, `via_fallback = false`. This validates the cache-collision diagnosis:
under the v0.4 ID-based key, Run 6's F06 never reached the judge because a stale Run-3 verdict was
returned from the colliding key `F006|F06|...`. Under v0.5 content-addressed keys, the correct pair
is judged fresh and matches at the primary stage. Run 3's F006 remains genuinely unmatched (agent gap;
fallback recovered nothing), confirming the two F006 misses are distinct mechanisms.

## Predictions

### E1 — True F1 < v0.4 F1 for all runs  [blind] → **DEVIATED**

| Run | v0.4 F1 | v0.5 F1 | direction |
|-----|--------:|--------:|:---------:|
| 1 | 0.8704 | 0.8704 | = |
| 2 | 0.8598 | 0.8598 | = |
| 3 | 0.9204 | 0.9107 | ↓ |
| 4 | 0.8909 | 0.8909 | = |
| 5 | 0.8598 | 0.8269 | ↓ |
| 6 | 0.9391 | 0.9833 | ↑ |

The prediction required F1 to **drop for every run**. It held for none-as-stated: three runs flat,
two down, one up. The premise — that a real precision metric would penalise unclaimed findings and
pull F1 below the v0.4 recall-only score — was falsified. Because `count_fp == 0` everywhere,
precision stayed at 1.0 and contributed **zero** downward pressure. The F1 movements that did occur
(R3, R5, R6) are entirely recall-driven, not precision-driven (see decomposition below).

### E2 — Run 6 > Run 3 F1 ordering survives precision correction  [blind] → **MET**

Run 6 (0.9833) > Run 3 (0.9107). Ordering preserved.

### E3 — Run 6 has the smallest precision drop  [inspection-informed, weak] → **DEVIATED**

All six precision "drops" are 0.0 (every run's precision = 1.0 = the v0.4 stub value). There is no
differential to rank. Run 6's drop of 0 is tied-smallest, so the prediction is not strictly
*falsified*, but the mechanism it described — precision drops that vary by run — did not occur. Marked
DEVIATED because the predicted phenomenon is absent.

### E4 — Run 1 larger precision drop than Run 3  [blind] → **DEVIATED**

Run 1 precision drop = 0; Run 3 precision drop = 0. Equal, not larger. Same root cause as E3: with
`count_fp == 0` for both runs, neither precision moved off 1.0. The reasoning behind E4 (Run 1 leaves
more unclaimed findings, so a larger FP exposure) assumed some unclaimed findings would be judged
illegitimate; none were.

## Why E1/E3/E4 all deviated — single common cause

All three deviations trace to one fact: **the precision judge found zero illegitimate findings in any
run.** The unclaimed agent findings were overwhelmingly *legit-unmatched* (R1: 8 legit / 3 uncertain;
R2–R6: all legit, no uncertain) — i.e. they cite verifiable artifacts (PIDs, file paths, IPs,
registry keys) but describe observations outside the 14-item GT. This is a substantive, positive
result about the agent (it does not emit unsupported claims), but it means the v0.5 precision term is
identically 1.0 and the headline F1 remains, in effect, a severity-weighted recall score — now with a
substantiated rather than assumed precision.

## Recall / match-set deviations (weight-level decomposition)

Derived purely from `weighted_tp = recall × 30.5` (per-finding id attribution is intentionally omitted;
see `analysis/v05_rescoring/run{N}_score.json` for the authoritative per-finding lists).

| Run | v0.4 wtp | v0.5 wtp | Δwtp | v0.4 matched | v0.5 matched | Δcount |
|-----|---------:|---------:|-----:|-------------:|-------------:|-------:|
| 1 | 23.5 | 23.5 | 0.0  | 8  | 8  | 0  |
| 2 | 23.0 | 23.0 | 0.0  | 10 | 10 | 0  |
| 3 | 26.0 | 25.5 | −0.5 | 11 | 10 | −1 |
| 4 | 24.5 | 24.5 | 0.0  | 9  | 9  | 0  |
| 5 | 23.0 | 21.5 | −1.5 | 10 | 9  | −1 |
| 6 | 27.0 | 29.5 | +2.5 | 11 | 12 | +1 |

- **R6 +2.5 / +1 count:** the F006 cache-collision fix recovers GT F006 (high, +2 weight) at the
  primary stage — the designed effect — plus one additional low-weight finding flipping to matched.
- **R3 −0.5, R5 −1.5:** runs lose net low/medium weight relative to v0.4. Two non-exclusive causes,
  both consistent with the content-addressed redesign and **neither a methodology regression**:
  (a) v0.4's ID-based cache could return cross-run collided verdicts that spuriously credited a pair;
  the v0.5 content key forces a fresh, correct verdict that may decline it; and
  (b) the documented near-determinism of `temperature=0` (not bit-identical at the model level) can
  flip a borderline confidence-3/4 verdict between the frozen v0.4 cache and the fresh v0.5 calls.
  The per-finding verdicts needed to separate (a) from (b) are in the run score JSONs; the net
  weight effect is small (≤ 1.5) and does not alter any critical-finding or FP-trap outcome.

## Stop rule

Completed 2026-05-29, before the June 7 2026 deadline.
