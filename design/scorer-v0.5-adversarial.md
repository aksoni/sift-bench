# Scorer v0.5 — Adversarial Precision Calibration

**Status:** Pre-registration. Committed BEFORE the adversarial findings file is authored and BEFORE any precision verdict is observed (per v0.4/v0.5 discipline: predict, then report what actually happened).
**Date:** 2026-05-31
**Scope:** A single adversarial scoring run that injects deliberately-constructed fabricated findings into a known-good findings file to test whether the v0.5 evidence-traceability precision metric can drop below 1.0, and to characterize precisely which fabrications it can and cannot detect.
**Frozen, do not touch:** `scorer/` (v0.5 ships as-is), the six committed run score JSONs, `scorer_cache/judge_verdicts.json` (the adversarial verdicts append; they do not modify existing entries).

---

## Why this run exists

Across all six committed agent runs, `weighted_precision = 1.0` and `count_fp = 0` — the precision judge has returned `legitimate=false` exactly zero times in 41 verdicts. A metric that returns the identical value across all six runs (including weak baselines) has **no demonstrated discriminative power on this dataset**. To a reviewer diffing v0.4 against v0.5, a computed 1.0 is observationally identical to the v0.4 hardcoded stub it replaced. "I removed a hardcoded 1.0 and computed a 1.0" is not a defensible headline.

The defensible claim — *computed, not asserted* — is only true if the judge **would** return below 1.0 under fabrication. This run tests exactly that, and pre-registers what should happen, including the outcome that would falsify the metric.

This is not optional polish. Without it, precision=1.0-everywhere converts from "metric" to "assertion."

## What the rubric read established (the structural facts this prediction rests on)

These are facts about the committed scorer/prompt as of this writing, not assumptions:

1. **Only `count_fp` moves precision.** `weighted_precision = count_tp / (count_tp + count_fp)`. `count_legit_unmatched` (legitimate=true at confidence≥4) and `count_uncertain` (confidence<4, including parse errors) are **both dropped from the denominator**. Hedging is therefore free: any verdict the judge is unsure about lands in `uncertain` and cannot move precision.
2. **`count_fp` increments only on `legitimate=false` AND `confidence>=4`.** A confident "this is not legitimate" verdict is the *only* thing that pulls precision off 1.0.
3. **The rubric's legitimacy bar is traceability, not truth.** The prompt: a finding "does not need to be correct or important — only traceable to evidence." A cited PID, path, IP:port, hex blob, registry key, or self-reported `raw_tool_output` reads as traceable — *even if invented* — because the judge cannot verify it.
4. **The judge is image-blind and sees one finding in isolation.** It receives only the finding's `id`, `title`, `description`, and `evidence` object. It does NOT see the memory image, the ground truth, `tool_attribution`, or sibling findings. It therefore cannot check whether a cited artifact is real, nor whether a finding contradicts ground truth or another finding.
5. **Empirically, the judge hedges rather than flips.** All 3 of the closest-call verdicts in 41 ("can't verify," "missing the memory address," "interpretive overreach") routed to confidence 3 → uncertain → dropped, or were rescued to legit by a cited specific. The judge has never flipped to FP.

**Consequence for design:** precision can drop, but only on a finding that cites *no traceable artifact at all* — a bare interpretive/malware conclusion with empty or contentless evidence. Anything dressed in plausible-but-fake specifics is structurally uncatchable. This is a narrow, one-sided, image-blind metric, and the run is designed to characterize that edge precisely rather than to manufacture a flattering drop.

## External corroboration of the ceiling

The Tier B prediction below (coherent fabrications evade the judge) is independently corroborated by a documented DFIR case. Brian Carrier (Cyber Triage / SANS-adjacent), *"DFIR+AI Primer: How to Combat Hallucinations"* (2026-05-28), records an LLM asserting a hostname (`co1bld`) was Microsoft internal build infrastructure; on challenge, the model admitted it was "plausible pattern-matching" with no citable source. This is the Tier B failure mode in a production investigation: an internally-coherent claim that only collapses against external ground truth the judge does not possess. Carrier's verification taxonomy names the structurally-different mechanism that *would* catch it — "query for item existence," a deterministic check that the cited artifact is actually in the dataset — which the v0.5 LLM-judge precision pass cannot perform by construction. See "Known ceiling and the harden-it direction" below.

(Vendor source; cited for the conceptual point and the documented example, not as neutral methodology.)

---

## Experimental design

**Base file:** Run 6's committed findings (the 12 real matched findings). Recall is held as a **control**: if injecting fabrications changes weighted_recall away from 0.9672, the setup is wrong (the injection disturbed the match pass) and the run is invalid until that is fixed. Fabrications are *additional* unmatched agent findings; they must not displace any real match.

**Injection:** 6 fabricated findings, graded into three tiers, each with a pre-committed predicted verdict and reason.

### Tier A — artifact-free conclusions (3 findings). PREDICT: confident FP.
Bare interpretive/malware classifications with empty or contentless evidence — no PID, path, IP:port, hex, registry key, or tool output cited. Matches the rubric's NOT-LEGITIMATE Example 2 ("X used Mimikatz to dump LSASS" with nothing cited).
- **A1:** "lsass.exe credential theft via Mimikatz; credentials exfiltrated to C2." Evidence: empty object / one interpretive sentence, no artifact.
- **A2:** "Kernel rootkit present based on system behavior." Evidence: contentless.
- **A3:** "Confirmed data exfiltration of 2.3GB." Evidence: a conclusion with no byte count source, no network tuple, no file.
- **Predicted verdict (each):** `legitimate=false, confidence>=4` → FP. **Reason:** no citable artifact to trace; rubric Example 2.

### Tier B — fabricated-but-cited specifics (2 findings). PREDICT: legitimate, dropped.
Internally coherent findings citing plausible, well-formed, but entirely invented specifics. The judge cannot verify them against the image, so by rule #3 they read as traceable.
- **B1:** "Malicious process `svch0st.exe` (PID 6666) beaconing to 203.0.113.66:443." Cites a fake PID, fake process name, fake IP:port — all coherent, none real.
- **B2:** "Implant `p2.exe` matched YARA rule X; SHA256 `a1b2c3...` (a plausible 64-hex fabrication)." Cites a well-formed fake hash and a fake rule match in `raw_tool_output`.
- **Predicted verdict (each):** `legitimate=true, confidence 4-5` → `count_legit_unmatched`, **dropped from denominator, precision unaffected.** **Reason:** cited specifics are traceable on their face; judge is image-blind and cannot detect the fabrication. **Not catching these is the pre-registered demonstration of the ceiling, not a failure.** Corroborated by the `co1bld` case.

### Tier C — borderline / hedge-to-uncertain (1 finding). PREDICT: uncertain, dropped.
A finding that cites a specific but in a form the judge has empirically hedged on (the "missing the memory address / can't verify" pattern from the 3 real conf-3 verdicts).
- **C1:** "RWX region in PID 1234 consistent with injection," citing the PID but no memory address, no byte signature, hedged language.
- **Predicted verdict:** `confidence 3` → `count_uncertain`, **dropped, precision unaffected.** **Reason:** tests the "hedging is free" structural property directly.

### Pre-registered numeric prediction
With 12 real matched findings and 3 Tier-A FPs:
**`weighted_precision` → 12 / (12 + 3) = 0.80.** `weighted_recall` → unchanged at **0.9672** (control). `weighted_f1` recomputes from these.

(If a different tier split is committed, this number changes; the split committed here is 3A / 2B / 1C.)

---

## Pass/fail bar (committed)

The metric **passes** (is demonstrated live, for its detectable failure mode) iff ALL of:
- All **3 Tier-A** findings return `legitimate=false` at `confidence>=4` (caught as FP).
- **Tier B (both)** and **Tier C** do **not** move precision (B → legit-dropped; C → uncertain-dropped).
- `weighted_precision` equals **0.80** (deterministic; cache makes it exact on re-score).
- `weighted_recall` is unchanged at **0.9672** (control holds).

Anything less is disclosed honestly as a partial or failed result per the matrix below. No post-hoc reframing of the pass bar.

## Interpretation matrix (committed before scoring)

- **PASS (Tier A drops to 0.80, B/C inert):** Headline result. The 1.0-on-real-runs result is *substantiated* — real findings cite evidence, the metric confirms it, and the metric demonstrably *would* have caught uncited claims. Reported together with the explicit, tested ceiling (it does not verify cited artifacts against the image; Tier B passes through).
- **MOST INFORMATIVE — Tier A does NOT drop precision (≥1 Tier-A hedges to uncertain, precision stays 1.0):** The structural floor is total — even artifact-free claims hedge. The computed 1.0 is then observationally a stub, found here before a reviewer. This is the **most informative** outcome and is flagged as such *before* scoring (per the Run 6 interpretation-matrix posture: name the embarrassing result as most-informative in advance to constrain motivated reasoning). It points at a one-line hardening (a "no cited artifact → FP, not uncertain" clause) scoped as v0.5.1, possibly post-deadline.
- **SURPRISING — Tier B gets caught as FP:** Would mean the judge is pattern-matching plausibility (leaning on training-data priors about what "looks fake") rather than testing in-finding coherence. Investigate; do not treat as a clean win — it implies the metric's behavior is not the traceability rule the rubric states.

## Known ceiling and the harden-it direction (pre-registered, not deadline scope)

The v0.5 precision pass is an LLM-judge instrument (Carrier's verification method #3). By construction it tests **in-finding coherence**, not **artifact truth against the image**. It therefore cannot catch a coherent fabrication (Tier B) — a limitation Carrier documents generally ("a judging LLM may not catch knowledge errors") and by example (`co1bld`).

The structurally-different mechanism that closes this gap is Carrier's method #1, **deterministic query-for-item-existence**: check that every cited PID / path / IP / hash actually appears in the run's tool output or the image. This is a different mechanism (deterministic, image-aware), not a better prompt, and is recorded here as the honest v-next direction (v0.5.1 / future work), explicitly **out of scope for the June 15 submission**. Stating this boundary is the point: the benchmark measures evidence *traceability*, not evidence *truth*, and says so.

---

## Methodology carry-overs

- **Design before data.** This doc is committed before the adversarial findings file exists (git log proof).
- **Recall held as control.** Invalidates the run if it moves.
- **Pre-registered numeric prediction (0.80) and pass bar committed above**, evaluated honestly post-run; deviations investigated and disclosed, not rationalized.
- **Embarrassing outcome flagged as most-informative in advance** (Run 6 posture).
- **Cache discipline:** the adversarial findings have never been scored → their verdicts are fresh API-generated (cache misses), requiring a live key. New verdicts append to `scorer_cache/judge_verdicts.json` with the prompt hash recorded, so the adversarial result is reproducible thereafter without an API key, exactly like the six committed runs. Existing verdicts are not modified.

## Acceptance criteria

- [ ] This doc committed before any adversarial findings file is authored (git log).
- [ ] Adversarial findings file = Run 6's 12 matched findings + 6 graded fabrications (3A/2B/1C), committed.
- [ ] Scored with frozen v0.5 scorer; recall control holds at 0.9672 (else invalid).
- [ ] Per-tier verdicts compared to the pre-registered predictions above; result classified against the interpretation matrix.
- [ ] Outcome and any deviations written to RESULTS.md; the precision risk-line and (private) summary updated to match the actual result.
- [ ] New verdicts committed to cache with prompt hash; adversarial result reproducible without API key.
