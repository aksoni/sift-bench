# SIFT-Bench

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
- **Demo result:** Best run (Run 6) found all 5 critical findings, caught all 3 false-positive traps, and scored 0.9391 on the v0.4 benchmark metric.
- **What to inspect:** [`RESULTS.md`](RESULTS.md), [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json), [`cases/srl-2018/run6_reports/`](cases/srl-2018/run6_reports/), [`scorer/`](scorer/).
- **No dataset?** The memory image is not redistributable, but committed run outputs, cached judge verdicts, and unit tests allow full review without it — see [Reviewing without the memory image](#reviewing-without-the-memory-image) below.

---

## Why this is interesting

Most agentic DFIR demos run an agent and show the output. SIFT-Bench does three things that most won't:

1. **A benchmark that scores analytical reasoning, not just discovery.** Ground truth includes severity-weighted findings, **false-positive traps** (artifacts that look suspicious under shallow analysis but are benign when checked against deeper forensic evidence — the agent must recognize and retract them), and **negative assertions** (the agent must actively verify the absence of expected behaviors, not silently omit them). Synthesis findings require the agent to connect process relationships, not just list them.

2. **A mandatory self-correction phase in the agent.** After investigation, the agent audits its own findings against known false-positive patterns and either CONFIRMS or RETRACTS each one with documented reasoning. Pre- and post-correction state are captured separately so the retraction itself is a scored artifact.

   **Example:** The agent initially flags OUTLOOK.EXE memory as injected code (FP001). During self-correction it recognizes the 0xFFEEFFEE .NET CLR heap signature and retracts. The scorer awards credit for the correct retraction with evidence-backed reasoning — not for the initial flag, and not for a silent omission.

3. **Variance methodology.** Multiple runs scored with mean ± stdev rather than point estimates. The scorer produces bit-identical output on reruns from the committed verdict cache, so the measured variance is agent variance, not measurement noise.

---

## Architecture

Three-phase workflow defined in [`CLAUDE.md`](CLAUDE.md):

1. **INVESTIGATE + ENRICH** — nine-step Volatility 3 methodology (psscan → pstree → cmdline → netscan → malfind → filescan → getsids → dlllist → registry/svcscan persistence check), with inline YARA scanning and file hashing via MCP tools when available.

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

Scored by **scorer v0.4** (LLM-as-judge semantic matching, `claude-sonnet-4-6`, verdicts cached in `scorer_cache/`). Under v0.4, precision is approximated at 1.0, so scores should be read as **recall-weighted benchmark scores** rather than true F1. Scorer v0.5 (evidence-traceability precision, per-pair fallback) is implemented and pending re-scoring.

| Run | Config | v0.4 Score | Recall¹ | Critical (must-find) | FP traps | Neg. assertions | Matched |
|-----|--------|---:|-------:|---------------------:|---------:|----------------:|--------:|
| 1 | Baseline CLAUDE.md | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 | 8/14 |
| 2 | + `dlllist` + persistence check | 0.8598 | 0.7541 | 4/5 ✗F005 | 2/3 | 3/5 | 10/14 |
| 3 | + output schema pin | 0.9204 | 0.8525 | **5/5** | 3/3 | 3/5 | 11/14 |
| 4 | + MCP server (hash_file + yara_scan) | 0.8909 | 0.8033 | **5/5** | 3/3 | 3/5 | 9/14 |
| 5 | + strengthened MCP prohibitions (gate² failed) | 0.8598 | 0.7541 | 4/5 ✗F003 | 3/3 | 4/5 | 10/14 |
| 6 | gate met — MCP tools live | **0.9391** | 0.8852 | **5/5** | 3/3 | 3/5 | 11/14 |

¹ Recall is severity-weighted (critical=4, high=2, medium=1, low=0.5) so it does not increase monotonically with raw matched count.  
² **Gate** = the pre-run check confirming Claude Code had loaded the MCP server and could call the enrichment tools. Run 5 gate failed: `.mcp.json` was at the wrong path; server not loaded.

**Best result: Run 6, score = 0.9391** — first run with MCP enrichment tools live end-to-end. All 5 critical findings, all FP traps caught. Post-tuning baseline (N=2, runs 2+3): mean score = 0.890 ± 0.030. See [`RESULTS.md`](RESULTS.md) for full E1–E6 evaluation, run-by-run breakdown, and scorer evolution.

v0.4 scores are lower than v0.3 (0.971 post-tuning mean) because the LLM judge removes false credits that keyword overlap was granting. The lower number is the more honest one.

---

## Reviewing without the memory image

The SANS FOR508 SRL-2018 image is not redistributable. You can still review the benchmark without it:

```bash
# Re-score the best run from committed cache (no API key needed)
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json

# Run unit tests (94 tests; no memory image or API key needed)
python -m unittest discover -s tests
```

Expected score for the run6 command: `v0.4_score: 0.9391, recall: 0.8852, critical: 5/5, fp_traps: 3/3, negative_assertions: 3/5, matched: 11/14` (bit-identical from committed cache).

Also inspect:
- [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json) — hand-authored ground truth with version history
- [`cases/srl-2018/run6_reports/`](cases/srl-2018/run6_reports/) — best run investigative narrative and structured findings
- [`RESULTS.md`](RESULTS.md) — full run-by-run breakdown with pre-registered expectation evaluation
- [`design/judge_test_cases.json`](design/judge_test_cases.json) — locked LLM judge regression cases

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

## Reproducing

**Requirements:**
- SANS SIFT Workstation 3.0 (Ubuntu 24.04, x86-64) — tested environment. Volatility 3 ≥ 2.27 available as `vol` on PATH via pipx.
- Claude Code ≥ 2.1
- Python 3.10+ with `pip install -r requirements.txt` (scorer requires `anthropic` and `jsonschema`; first-run API calls require `ANTHROPIC_API_KEY`)
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

- **The scorer has been iterated four times** during development: v0.1 → v0.2 fixed double-matching, v0.2 → v0.3 fixed hash-seed nondeterminism, v0.3 → v0.4 replaced keyword overlap with LLM-as-judge for principled semantic matching. See [`RESULTS.md`](RESULTS.md) for the full evolution.

- **Variance across runs is treated as signal, not noise.** Stable behaviors (all 5 critical findings, Outlook/CLR retractions, core attack chain) form the backbone of the demo. Unstable behaviors (which exact FPs get caught run-to-run) are reported with mean ± stdev. See [`RESULTS.md`](RESULTS.md) for the full breakdown.

---

## Known limitations

- **Restricted evidence image:** The SRL-2018 memory image is not redistributed. Reviewers can inspect committed run outputs and rerun the scorer using cached judge verdicts without it.
- **v0.4 precision approximation:** Scorer v0.4 approximates precision at 1.0, so v0.4 scores are recall-weighted benchmark scores, not true F1. Scorer v0.5 (implemented in this repo; pending re-scoring) adds evidence-traceability precision via LLM judge.
- **Stable miss — F011** (`spsql` NTUSER.DAT loaded in memory): missed across all runs. No methodology step explicitly checks loaded user hives. Recoverable with an additional `windows.registry.hivescan` step.
- **Small sample size:** Post-tuning variance is based on N=2 runs; larger N would provide tighter confidence intervals (currently σ = 0.030).
- **Single case:** The benchmark has one hand-authored case. The design supports additional cases; they are not yet included.
- **K=3 pre-filter ceiling:** If the correct agent finding ranks below 3rd by keyword overlap, the judge never evaluates it. One likely instance identified in Run 6 (GT F006 scoring artifact).

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
