# SIFT-Bench

> **Judges: no evidence image and no API key needed.** Run `make judge-fast` (or follow [`JUDGE_GUIDE.md`](JUDGE_GUIDE.md)) — every published score replays deterministically from the committed judge-verdict cache. Full agent reproduction is available if you have the SANS FOR508 SRL-2018 image. Reproducibility verified on a clean container: [`analysis/clean-vm-dryrun-2026-06-09.log`](analysis/clean-vm-dryrun-2026-06-09.log).

SIFT-Bench tests whether an autonomous DFIR agent can investigate a compromised Windows memory image, explain its evidence, retract false leads, and verify that certain suspected behaviors did not occur — not just list IOCs.

**A benchmark and evaluation framework for autonomous DFIR agents, with a self-correcting reference implementation built on Claude Code + SIFT Workstation + Volatility 3.**

It includes a hand-authored ground truth, a deterministic replayable scorer with committed LLM-judge verdict cache, a mandatory self-correction workflow, a custom MCP (Model Context Protocol) server for YARA and hash enrichment, and a dual-schema findings validator.

Solo submission to the [Find Evil! hackathon](https://findevil.devpost.com) (Apr 15 – Jun 15, 2026).

[![tests](https://github.com/aksoni/sift-bench/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/aksoni/sift-bench/actions/workflows/tests.yml)
![tested-on-sift](https://img.shields.io/badge/tested%20on-SIFT%203.0%20%28Ubuntu%2024.04%29-blue)

---

## TL;DR for judges

- **Problem:** DFIR agents can produce plausible but unsupported findings.
- **Solution:** SIFT-Bench evaluates evidence-backed findings, false-positive retractions, negative assertions, and methodology coverage — not keyword matches.
- **Demo result:** Best run (Run 6) found all 5 critical findings, caught all 3 false-positive traps, and scored 0.9833 on the v0.5 benchmark metric.
- **What to inspect:** [`DATASET.md`](DATASET.md), [`RESULTS.md`](RESULTS.md), [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json), [`cases/srl-2018/run6_reports/`](cases/srl-2018/run6_reports/), [`scorer/`](scorer/).
- **Reproducible without the image:** scores replay deterministically from committed run outputs, cached judge verdicts, and unit tests — no memory image and no API key required (`make judge-fast`). See [Fast review without the memory image](#fast-review-without-the-memory-image) below.

---

## Why this is interesting

Most agentic DFIR demos run an agent and show the output. SIFT-Bench does three things that most won't:

1. **A benchmark that scores analytical reasoning, not just discovery.** Ground truth includes severity-weighted findings, **false-positive traps** (artifacts that look suspicious under shallow analysis but are benign when checked against deeper forensic evidence — the agent must recognize and retract them), and **negative assertions** (the agent must actively verify the absence of expected behaviors, not silently omit them). Synthesis findings require the agent to connect process relationships, not just list them.

2. **A mandatory self-correction phase in the agent.** After investigation, the agent audits its own findings against known false-positive patterns and either CONFIRMS or RETRACTS each one with documented reasoning. Pre- and post-correction state are captured separately so the retraction itself is a scored artifact.

   **Example:** The agent initially flags OUTLOOK.EXE memory as injected code (FP001). During self-correction it recognizes the 0xFFEEFFEE .NET CLR heap signature and retracts. The scorer awards credit for the correct retraction with evidence-backed reasoning — not for the initial flag, and not for a silent omission.

3. **Variance methodology.** Multiple runs scored with mean ± stdev rather than point estimates. The scorer produces bit-identical output on reruns from the committed verdict cache, so the measured variance is agent variance, not measurement noise.

---

## Architecture

> **Architecture & trust boundaries (Criterion 4): see [`ARCHITECTURE.md`](ARCHITECTURE.md)** — the
> architectural patterns, the inherited-vs-built provenance boundary, the three trust boundaries,
> and the prompt-based vs. architectural guardrail distinction (including the documented Run 4
> bypass and which enforcement layer actually closed it).

Three-phase workflow defined in [`CLAUDE.md`](CLAUDE.md):

1. **INVESTIGATE + ENRICH** — nine-step Volatility 3 methodology (psscan → pstree → cmdline → netscan → malfind → filescan → getsids → dlllist → registry/svcscan persistence check), with YARA scanning and file hashing routed through MCP tools rather than ad hoc inline commands when the MCP gate is met.

2. **SELF-CORRECT** — evidence audit (every finding must cite tool output), methodology check, consistency check, false-positive review against known patterns. Pre-correction findings saved before any changes.

3. **REPORT** — investigative narrative (markdown), structured findings (JSON conforming to pinned schema), execution log. MITRE ATT&CK mapping, UTC timestamps.

```
Memory image
    │
    ▼
Claude Code agent + CLAUDE.md methodology
    │
    ├──▶ Volatility 3 plugins  (psscan · pstree · cmdline · netscan · malfind · ...)
    ├──▶ MCP tools: yara_scan · hash_file  (sift-bench-enrichment server)
    │
    ▼
Pre-correction findings  (findings_pre_correction.json)
    │
    ▼
Self-correction audit
    │
    ▼
Post-correction findings + investigative report
    │
    ▼
SIFT-Bench scorer
    │
    ▼
Weighted recall · FP trap score · Negative assertion score · Methodology score
```

The MCP server (`yara_scan`, `hash_file` tools) is designed to be extensible to VirusTotal, Censys, and other threat intel sources.

### LLM-judge safeguards

The scorer uses an LLM judge for semantic matching, but reruns are deterministic once verdicts are cached:

- Judge prompts versioned in `scorer/prompts/`
- Regression cases locked in `design/judge_test_cases.json`
- Verdicts cached content-addressably in `scorer_cache/judge_verdicts.json`
- No-API reruns when all verdicts are cached (first run requires `ANTHROPIC_API_KEY`)
- `JudgeParseError` (malformed verdict) logs a warning and skips the pair rather than aborting a multi-hour run
- Scorer v0.5 adds per-pair fallback matching and evidence-traceability precision

---

## Results

Benchmark: SANS FOR508 Stark Research Labs case SRL-2018, base-rd01 memory image. Ground truth v1.1: 14 findings (5 critical), 3 false-positive traps, 5 negative assertions.

Scored by **scorer v0.5** (LLM-as-judge semantic matching, `claude-sonnet-4-6`, verdicts cached in `scorer_cache/`), which adds real evidence-traceability precision and per-pair fallback matching. The **v0.5 F1** column is the current headline metric; the **v0.4 Score** column is retained alongside it as the prior scorer iteration, for comparison. Under v0.4, precision was approximated at 1.0, so v0.4 numbers read as **recall-weighted benchmark scores** rather than true F1; the remaining columns (recall, critical must-find, FP traps, negative assertions, matched) report the v0.5 re-scoring.

| Run | Config | v0.4 Score | v0.5 F1 | Recall¹ | Critical (must-find) | FP traps | Neg. assertions | Matched |
|-----|--------|---:|---:|-------:|---------------------:|---------:|----------------:|--------:|
| 1 | Baseline CLAUDE.md | 0.8704 | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2 | + `dlllist` + persistence check | 0.8598 | 0.8598 | 0.7541 | 4/5 ✗F005 | 2/3 | 3/5 | 10/14 |
| 3 | + output schema pin | 0.9204 | 0.9107 | 0.8361 | **5/5** | 3/3 | 3/5 | 10/14 |
| 4 | + MCP server (hash_file + yara_scan) | 0.8909 | 0.8909 | 0.8033 | **5/5** | 3/3 | 3/5 | 9/14 |
| 5 | + strengthened MCP prohibitions (gate² failed) | 0.8598 | 0.8269 | 0.7049 | 4/5 ✗F003 | 3/3 | 4/5 | 9/14 |
| 6 | gate met — MCP tools live | **0.9391** | **0.9833** | 0.9672 | **5/5** | 3/3 | 3/5 | 12/14 |

¹ Recall is severity-weighted (critical=4, high=2, medium=1, low=0.5) so it does not increase monotonically with raw matched count.  
² **Gate** = the pre-run check confirming Claude Code had loaded the MCP server and could call the enrichment tools. Run 5 gate failed: `.mcp.json` was at the wrong path; server not loaded.

**Best result: Run 6, v0.5 F1 = 0.9833** (v0.4 score 0.9391 under the prior scorer; the v0.5 gain is recall-driven, with precision now computed = 1.0 rather than stubbed — calibrated, see [`RESULTS.md`](RESULTS.md) and `design/scorer-v0.5-adversarial.md`) — first run with MCP enrichment tools live end-to-end. All 5 critical findings, all FP traps caught. Post-tuning baseline (N=2, runs 2+3): mean v0.4 score = 0.890 ± 0.030. See [`RESULTS.md`](RESULTS.md) for full E1–E6 evaluation, run-by-run breakdown, and scorer evolution.

v0.4 scores are lower than v0.3 (0.971 post-tuning mean) because the LLM judge removes false credits that keyword overlap was granting. The lower number is the more honest one.

Precision is 1.0 on all six real runs because the v0.5 judge found zero illegitimate unmatched findings. A pre-registered adversarial calibration that injected three artifact-free fabricated findings dropped precision to exactly **0.80**, confirming the precision judge penalizes unsupported claims rather than rubber-stamping them. Details in [`RESULTS.md`](RESULTS.md) and `design/scorer-v0.5-adversarial.md`.

---

## Fast review without the memory image

**The published scores replay deterministically from committed artifacts — no memory image and no API key required.** The scorer reads cached LLM-judge verdicts (`scorer_cache/judge_verdicts.json`) keyed on content hashes, so every number below reproduces bit-for-bit, offline, on any reviewer's machine. This is a deliberate reproducibility property, not a fallback: the determinism comes from the committed cache, not from re-querying a model. (The SANS FOR508 SRL-2018 image itself is not redistributable — but you do not need it to verify the results.)

**Fastest path: `make judge-fast`** runs the whole review (score + tests + evidence trace + retractions + MCP gate) in one command — see [`JUDGE_GUIDE.md`](JUDGE_GUIDE.md). The explicit steps:

```bash
# Install dependencies (anthropic + jsonschema; no API key needed for cached reruns)
python -m pip install -r requirements.txt

# Re-score the best run from committed cache (no API key needed)
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json

# Run unit tests (94 tests; no memory image or API key needed)
python -m unittest discover -s tests
```

Expected score for the run6 command: `weighted_f1: 0.9833, recall: 0.9672, precision: 1.0, critical: 5/5, fp_traps: 3/3, negative_assertions: 3/5, matched: 12/14` (bit-identical from committed cache; `precision: 1.0` is calibrated, not a stub — see RESULTS.md).

These three steps were verified from a clean `python:3.12-slim` container on 2026-06-09 — full transcript in [`analysis/clean-vm-dryrun-2026-06-09.log`](analysis/clean-vm-dryrun-2026-06-09.log) (no API key present; both numbers reproduced from cache; 94 tests pass).

Also inspect:
- [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json) — hand-authored ground truth with version history
- [`cases/srl-2018/run6_reports/`](cases/srl-2018/run6_reports/) — best run investigative narrative and structured findings
- [`RESULTS.md`](RESULTS.md) — full run-by-run breakdown with pre-registered expectation evaluation
- [`design/judge_test_cases.json`](design/judge_test_cases.json) — locked LLM judge regression cases
- [`cases/srl-2018/session_transcripts/`](cases/srl-2018/session_transcripts/) — raw Run 4 / Run 5 agent-run transcripts plus [`token_usage.json`](cases/srl-2018/session_transcripts/token_usage.json) (per-turn token totals; Run 6 transcript not retained — see the report's token-accounting note)

---

## Repository layout

```
sift-bench/
├── README.md
├── RESULTS.md                   Full benchmark results + scorer evolution
├── CLAUDE.md                    Agent config (methodology + output schema pin)
├── skills/
│   └── self-correction/SKILL.md Self-correction protocol
├── ground_truth/
│   └── base-rd01-v1.1.json      Hand-authored ground truth + version history
├── scorer.py                    CLI entrypoint (delegates to scorer/ package)
├── scorer/                      Scorer package
│   ├── scorer.py                Matching logic + score() function
│   ├── judge.py                 LLM-as-judge: judge_pair, judge_fallback_pair, judge_precision
│   ├── judge_cache.py           Content-addressed verdict cache + PrecisionVerdict
│   ├── validate_findings.py     Pre-flight findings schema validator (permissive + strict)
│   ├── checklist.py             Methodology checklist scorer (9-step)
│   ├── self_correction.py       Self-correction effectiveness scorer
│   └── prompts/
│       ├── judge_v0.4.txt            Primary match prompt (few-shot)
│       ├── judge_v0.5_fallback.txt   Fallback match prompt
│       └── judge_v0.5_precision.txt  Evidence-traceability precision prompt
├── scorer_cache/
│   └── judge_verdicts.json      Cached verdicts (committed; enables no-API reruns)
├── design/                      Pre-registered design docs
│   ├── scorer-v0.4.md
│   ├── scorer-v0.5.md           v0.5 design (committed before implementation)
│   └── judge_test_cases.json    Locked judge regression cases
├── tests/
│   ├── test_scoring_additions.py    Checklist + self-correction unit tests
│   ├── test_validate_findings.py    Dual-schema findings validator tests
│   ├── test_judge_cache.py          Judge cache kind-tagging tests
│   ├── test_judge_error_handling.py Judge loop resilience tests
│   ├── test_tool_executor.py        Tool executor output-flag tests
│   ├── test_mcp_server.py           MCP server tool tests
│   ├── test_yara_novel.py           Novel YARA rule tests
│   └── validate_judge.py            Judge prompt regression suite (v0.4 + v0.5)
├── mcp_server/                  YARA + hash enrichment MCP server
├── yara_rules/                  Detection rules
└── cases/
    └── srl-2018/                Per-case working area
        ├── run1_analysis/       Baseline run outputs
        ├── run1_reports/
        ├── run2_analysis/
        ├── run2_reports/
        ├── run3_analysis/
        ├── run3_reports/
        ├── run4_analysis/       MCP server registered but tools bypassed by agent
        ├── run4_reports/
        ├── run5_analysis/       Strengthened prohibitions (gate failed — server absent)
        ├── run5_reports/
        ├── run6_analysis/       Gate met — MCP tools live (best result)
        └── run6_reports/
```

---

## Full reproduction with the case image

This path re-runs the agent end-to-end and requires the SRL-2018 image. It is the bonus
path — the [fast review above](#fast-review-without-the-memory-image) verifies every
published score without it.

**Requirements:**
- SANS SIFT Workstation 3.0 (Ubuntu 24.04, x86-64) — tested environment. Volatility 3 ≥ 2.27 available as `vol` on PATH via pipx.
- Claude Code ≥ 2.1
- Python 3.10+ with `pip install -r requirements.txt` (scorer requires `anthropic` and `jsonschema`; first-run API calls require `ANTHROPIC_API_KEY`). Direct dependencies are **pinned (`==`)** to the versions resolved in the 2026-06-09 clean-container dry-run ([`analysis/clean-vm-dryrun-2026-06-09.log`](analysis/clean-vm-dryrun-2026-06-09.log)) for reproducible installs.
- A memory image to analyze (the SRL-2018 base-rd01 image is from the SANS FOR508 course and is not redistributable)

> **Non-SIFT hosts:** If `vol` is not on PATH, install via `pipx install volatility3` or invoke directly as `python3 /opt/volatility3-*/vol.py`. Update the `vol` invocations accordingly. All other tools (`fls`, `icat`, `bulk_extractor`) are standard DFIR packages available via apt.

**Setup:**

```bash
git clone https://github.com/aksoni/sift-bench.git
cd sift-bench
pip install -r requirements.txt

# Place your memory image at ./evidence/ (gitignored)
mkdir -p evidence
cp /path/to/memory.img evidence/

# Install the self-correction skill globally
mkdir -p ~/.claude/skills/self-correction
cp skills/self-correction/SKILL.md ~/.claude/skills/self-correction/
```

**Run the agent:**

```bash
cd cases/srl-2018
claude "Analyze the memory image at ../../evidence/<image>.img following the workflow defined in CLAUDE.md. Save all outputs to ./analysis/, ./exports/, and ./reports/."
```

Expect ~17 minutes wall time on a 4-vCPU / 16 GB VM.

**Score against ground truth:**

```bash
# Score a new run (requires ANTHROPIC_API_KEY on first run; subsequent runs use committed cache)
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json
```

The judge verdict cache (`scorer_cache/judge_verdicts.json`) is committed to the repo. Reviewers without API access get bit-identical output from the cache.

---

## Methodology notes

- **Ground truth was authored before any agent runs**, with documented version history. v1.1 changes (F010 reclassification from "suspicious" to false positive, addition of FP003 and NA005, expansion of methodology checklist) are recorded in the ground truth file's `version_history` field.

- **F010 reclassification** was resolved via hexdump evidence review confirming the 0xFFEEFFEE .NET CLR heap signature, not AI inference.

- **The scorer has been iterated four times** during development: v0.1 → v0.2 fixed double-matching, v0.2 → v0.3 fixed hash-seed nondeterminism, v0.3 → v0.4 replaced keyword overlap with LLM-as-judge semantic matching, and v0.4 → v0.5 added evidence-traceability precision, per-pair fallback matching, and content-addressed cache keys. See [`RESULTS.md`](RESULTS.md) for the full evolution.

- **Variance across runs is treated as signal, not noise.** Stable behaviors (all 5 critical findings, Outlook/CLR retractions, core attack chain) form the backbone of the demo. Unstable behaviors (which exact FPs get caught run-to-run) are reported with mean ± stdev. See [`RESULTS.md`](RESULTS.md) for the full breakdown.

---

## Known limitations

- **Restricted evidence image:** The SRL-2018 memory image is not redistributed. Reviewers can inspect committed run outputs and rerun the scorer using cached judge verdicts without it.
- **v0.4 precision approximation:** Scorer v0.4 approximated precision at 1.0, so v0.4 scores are recall-weighted benchmark scores, not true F1. Scorer v0.5 is now the active scorer and computes evidence-traceability precision; all six runs have been re-scored (2026-05-29).
- **Precision measures traceability, not full artifact truth:** v0.5 penalizes unsupported findings — a pre-registered adversarial calibration that injected three artifact-free fabrications dropped precision to 0.80 exactly as predicted — but it does not yet deterministically verify that every cited artifact exists in the original image. Coherent fabrications citing invented-but-traceable specifics can pass; a cited-artifact existence check is future work. See [`RESULTS.md`](RESULTS.md).
- **Stable miss — F011** (`spsql` NTUSER.DAT loaded in memory): missed across all runs. No methodology step explicitly checks loaded user hives. Recoverable with an additional `windows.registry.hivescan` step.
- **Small sample size:** Post-tuning variance is based on N=2 runs; larger N would provide tighter confidence intervals (currently σ = 0.030).
- **Single case:** The benchmark has one hand-authored case. The design supports additional cases; they are not yet included.
- **Keyword pre-filter ceiling:** The scorer uses a keyword pre-filter (top-K candidates) before LLM judging; if the correct agent finding is not surfaced as a candidate, the judge cannot recover it. Run 3's F006 miss is the clearest remaining example. A separate Run 6 F006 miss under v0.4 was later diagnosed as a cache-key collision (not a pre-filter ceiling) and is fixed in v0.5 by content-addressed cache keys.

---

## License

MIT. See [LICENSE](LICENSE).

The SANS FOR508 dataset used for the ground truth case is NOT covered by this license and is not redistributed in this repository.

---

## Acknowledgements

- SANS DFIR / FOR508 for the Stark Research Labs case dataset
- The Volatility Foundation for Volatility 3
- Anthropic for Claude Code and the Model Context Protocol (MCP)
- Protocol SIFT for the baseline forensic workflow this agent extends
