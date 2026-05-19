# Scorer v0.4 Design Note — LLM-as-Judge

**Status:** Draft, week 2 session 1. Author: aksoni. Committed before any v0.4 implementation or judge calls — git history is the receipt.

## Problem

v0.3 keyword-overlap matching has three documented failure modes from runs 1–3:

1. **False match:** GT F006 (rundll32 children) ↔ agent F07 (reflective PS in rundll32). Different findings, shared keywords ("rundll32", "PowerShell"), currently credited.
2. **Unstable match:** GT F013 (p.exe DLL profile) ↔ agent F06 (same finding). Same observation, scorer credits in runs 2+3 but missed in run 1 due to keyword-set variation.
3. **Weak false match:** GT F011 (NTUSER.DAT spsql) ↔ agent F07 (reflective PS). Different findings, weak keyword overlap on "PowerShell"/"process", scored 2 in some runs.

Root issue: keyword overlap can't distinguish "describes the same observation" from "shares vocabulary." Semantic understanding is required.

## Goal

Replace `match_finding`'s scoring logic with an LLM-as-judge call that returns a structured verdict on whether a GT-agent pair describes the same observation. Preserve v0.3's matching algorithm (greedy weight-sorted, claimed-agent tracking, lex tiebreak) and add the determinism guarantees needed to make rerun results bit-identical.

**Non-goal:** Use the LLM to *generate* matches. The judge only adjudicates pairs that pass a cheap pre-filter. This bounds cost and keeps the matching algorithm intact.

## Design

### Pipeline

```
For each GT finding (in severity-weight-sorted, lex-tiebroken order):
    candidates = agent_findings not yet claimed

    # Cheap pre-filter: top-K by keyword overlap (K=3)
    candidates = top_k_by_keyword_overlap(gt, candidates, K=3)

    # Order candidates for judge calls: pre-filter score desc, then lex agent ID asc
    candidates = sorted(candidates, key=lambda c: (-c.prefilter_score, c.agent_id))

    # LLM judge for each candidate
    for c in candidates:
        verdict = judge(gt, c)  # cached
        if verdict.match and verdict.confidence >= 4:
            score this pair, mark c as claimed, break
        elif verdict.confidence == 3:
            log warning for post-mortem
```

### Pre-filter: top-K, not threshold

The original draft proposed a keyword-overlap threshold tuned to admit the three known failure modes. That's underspecified — thresholds drift, distributions vary across runs, and "tuned to admit failure modes" reads as overfit.

Top-K (K=3) replaces this. For each GT finding, the judge sees the top 3 agent findings by keyword overlap score. Cost is predictable (14 GT × 3 candidates × 3 runs ≈ 126 calls). The K=3 ceiling is defensible: across runs 1–3, no GT finding had more than 2 plausible matches in practice, so K=3 carries one slot of headroom.

### Candidate ordering at the judge layer

Sort candidates by pre-filter score descending, then agent ID lexicographically. Without this, "first candidate to get a match verdict wins" depends on iteration order, which reintroduces non-determinism above the judge layer.

### Judge interface

```python
@dataclass
class JudgeVerdict:
    match: bool
    confidence: int  # 1-5
    reasoning: str   # logged, not used in scoring

def judge(gt_finding: dict, agent_finding: dict) -> JudgeVerdict:
    ...
```

Single API call per pair. Returns structured JSON. Reasoning field is logged for post-mortem review.

### Prompt

Few-shot prompt with the three documented failure modes as worked examples. Few-shot on the exact pairs the matcher needs to handle correctly is cheap, robust, and directly addresses the "primary subject" underspecification.

```
You are evaluating whether two findings from a memory forensics analysis
describe the same underlying observation. They may use different vocabulary,
different levels of specificity, or different framing.

A match means both findings reference the same process, file, registry key,
network connection, or behavioral mechanism as the primary subject. Shared
vocabulary without shared subject is NOT a match. The agent finding being a
more specific or more general version of the ground truth IS a match.

If two findings describe different mechanisms (spawning vs. injection,
dropping vs. moving, parent vs. child, etc.) involving the same tool or
process, they are NOT a match even if they share subject vocabulary.

Severity disagreement between findings (e.g., GT marked "high" vs. agent
marked "critical") is NOT disqualifying. Judge whether the same observation
is being described, not whether both parties agree on its impact.

Examples:

EXAMPLE 1 — NOT A MATCH (different mechanisms, shared vocabulary):
  GT: "Six rundll32.exe processes spawned as children of PowerShell, used as
       shellcode carriers"
  Agent: "Reflective PowerShell code loaded into a rundll32 host process"
  Verdict: {"match": false, "confidence": 5,
            "reasoning": "Both involve rundll32 and PowerShell but describe
            opposite mechanisms — children spawned vs. code injected into host.
            Different observations."}

EXAMPLE 2 — MATCH (same observation, different specificity):
  GT: "p.exe DLL profile shows WININET, crypto, and HTTP stack consistent with
       C2 client"
  Agent: "p.exe loaded DLLs include wininet.dll, crypt32.dll, suggesting
          network beacon capability"
  Verdict: {"match": true, "confidence": 5,
            "reasoning": "Same file (p.exe), same DLL evidence, same inference.
            Agent finding is slightly less specific but clearly the same
            observation."}

EXAMPLE 3 — NOT A MATCH (weak vocabulary overlap, different subjects):
  GT: "NTUSER.DAT registry hive for spsql account loaded into memory"
  Agent: "Reflective PowerShell process detected"
  Verdict: {"match": false, "confidence": 5,
            "reasoning": "GT is about a registry artifact for a specific user
            account. Agent finding is about a PowerShell process. No shared
            subject."}

Now evaluate:

GROUND TRUTH FINDING:
  ID: {gt.id}
  Title: {gt.title}
  Description: {gt.description}
  Evidence: {gt.evidence}

AGENT FINDING:
  ID: {agent.id}
  Title: {agent.title}
  Description: {agent.description}
  Evidence: {agent.evidence}

Return JSON only: {"match": bool, "confidence": 1-5, "reasoning": "..."}
```

The prompt is the riskiest design surface. The three examples above are the regression test suite — see Validation Plan.

### Determinism

Three sources of non-determinism to control:

1. **Model sampling.** Set `temperature=0`. **Note:** Anthropic's API at temperature=0 is *near-deterministic*, not bitwise-deterministic. Small floating-point variations in inference can flip outputs on borderline cases. First-time scoring of a pair is therefore subject to model-level near-determinism; the cache (below) is what makes *rerun* results bit-identical.

2. **API flakes / retries.** Wrap calls with retry logic (5 attempts, exponential backoff). On failure-after-retries: **persist all completed verdicts to the cache, then fail the whole scoring run.** No hybrid scoring regimes. Rerun resumes from the cache, so a failed run does not waste prior work.

3. **Result caching.** Cache verdicts keyed on:
   ```
   sha256(gt_id + agent_id + model_snapshot_id + sha256(prompt_template))
   ```
   - Starting with the Claude 4.6 generation, model IDs are dateless but still pinned snapshots (per Anthropic's model versioning docs). `claude-sonnet-4-6`
     is the canonical, fixed model ID — Anthropic does not update the weights behind an existing 4.6+ ID. For older models (4.5 and earlier), use the
     dated snapshot string instead.
   - Hashing the prompt template content means editing the prompt automatically invalidates affected entries. No manual `prompt_version` bookkeeping.
   - Cache file checked into the repo at `scorer_cache/judge_verdicts.json`.

### Cost estimate

3 runs × 14 GT findings × 3 candidates = 126 calls as an upper bound. Actual
call count will be lower for GT findings with fewer than 3 keyword-overlapping
candidates (pre-filter requires nonzero overlap). Sonnet 4.6 ~500 tokens in,
~150 tokens out per call. Well under $1 total. Cache makes subsequent reruns
free.

## Validation plan

Before publishing v0.4 numbers, the judge must pass these tests:

1. **The three documented failure modes resolve correctly.** F006/F07 → no match. F013/F06 → match in all three runs. F011/F07 → no match. These are saved as `tests/judge_test_cases.json` and are the prompt's regression suite.
2. **Stable matches stay stable.** F001 (p.exe), F002 (spsql), F003 (WMI), F004 (C2), F005 (PS C2 shell) all match across runs 2 and 3 as before. **Failure on this test indicates prompt regression; iterate the prompt before proceeding to test 3.**
3. **Deterministic spot-check of 5 matches.** Select by `sha256(gt_id + agent_id) % N == 0` for the first 5 hits across all runs. Manual review of reasoning field. "I picked five" is not a defensible methodology; reproducible selection is.
4. **Rerun-determinism test.** Run scorer twice on a populated cache. Bit-identical output.

If any fail, iterate the prompt. Each iteration invalidates the affected cache entries automatically via the prompt-template hash.

## Headline-number expectations (written before any judge call)

The three documented failure modes are all "currently credited, shouldn't be" or "currently inconsistent, should match every run." Net direction:

- Run 1: F1 probably unchanged or slightly down (F011 false credit removed)
- Run 2: F1 probably up slightly (F013 already credited; F011 not credited)
- Run 3: F1 probably down slightly (F011 false credit removed, F006/F07 false credit removed)

Mean and σ both move. **The story to tell is not "F1 went up."** It is: "we replaced a known-fragile matcher with one that's defensible on inspection, disclosed how the headline numbers moved, and committed our expectations before measuring." The eval-engineering signal is in *that*, not in the new number being higher.

## Out of scope for v0.4

- Replacing the matching algorithm itself (still greedy weight-sorted)
- Multi-turn judge (one call per pair, no chain-of-thought tooling)
- Judge ensembling or self-consistency (single call, temperature 0)
- **Using the judge to rescore FP traps or negative assertions.** FP traps have structured anchor data (specific process names, PIDs, signatures) where exact-string matching is more reliable than LLM judgment. If the agent retracts "Outlook.exe (PID 8128)" we want a regex-style verifier, not an LLM that might charitably credit "the Outlook false positive" with no PID mentioned. A future iteration should not "complete" v0.4 by extending the judge to FP/NA.

## Decisions (previously open questions)

- **Confidence threshold = 4.** Calibrating against three pairs is too few to distinguish 3 from 4 robustly; conservative threshold puts the burden of proof on inclusion, which is the right direction for a benchmark.
- **Confidence-3 verdicts:** with threshold 4, these don't match. Don't introduce a "match but flag" third state — it complicates the scoring model with no clear use case. Logged as warning for post-mortem.
- **Score derivation:** judge returns match/no-match only. Score derives from GT severity weight as in v0.3. Judge confidence is an inspection signal, not a scoring signal. Mixing them collapses two different things into one number, which is what got v0.3 in trouble.

## Pinned model snapshot

**Snapshot ID:** `claude-sonnet-4-6`

This is the exact model ID used for all judge calls in v0.4. Per Anthropic's 4.6-generation versioning, dateless IDs are themselves pinned snapshots — weights and configuration behind `claude-sonnet-4-6` are fixed. Pinned here so the cache key has a stable reference and the "committed expectations before measuring" claim is verifiable in git history.

## Pinned prompt template

**SHA-256:** `d6cfae8cabb9286aa5f387490eab4166fad24981b01c4640fe968d14eb48d678`
**Path:** `scorer/prompts/judge_v0.4.txt`

This is the hash of the exact prompt content used for all v0.4 judge calls.
Cache entries in `scorer_cache/judge_verdicts.json` reference this hash. Any
edit to the prompt file produces a new hash and automatically invalidates
affected entries. Note: literal JSON braces in the worked examples are escaped
as `{{`/`}}` in the template file so Python's `.format()` does not interpret
them as placeholders — they render correctly as `{`/`}` in the final prompt.

## Implementation order

1. Commit this doc, with the model snapshot ID pinned (see "Pinned model snapshot" above) and `design/judge_test_cases.json` populated with expected verdicts for the three failure-mode pairs. Both files committed in the same commit. (Now.)
2. **No exploratory judge calls before step 1 lands.** Sampling the judge's output before locking expectations destroys the adversarial property of the regression suite.
3. Implement `judge()` with the prompt above. Run against `design/judge_test_cases.json`. Iterate prompt if any fail.
4. Implement cache with content-addressed keys.
5. Wire judge + cache into `match_finding`. Add candidate ordering rule.
6. Implement fail-on-API-error with cache-persist behavior.
7. Rescore runs 1, 2, 3. Cache populates.
8. Run rerun-determinism test.
9. Run deterministic spot-check.
10. Update README, RESULTS.md, summary doc with new canonical numbers. Disclose the directional movement as predicted in the headline-number section above.
