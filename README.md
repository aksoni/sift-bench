# SIFT-Bench

**A benchmark and evaluation framework for autonomous DFIR agents, with a self-correcting reference implementation built on Claude Code + SIFT Workstation + Volatility 3.**

SIFT-Bench measures evidence quality, false-positive handling, negative assertion verification, and analytical rigor — not just IOC extraction. Includes a hand-authored ground truth, a deterministic standalone scorer, and a custom MCP server for YARA and hash enrichment.

Solo submission to the [Find Evil! hackathon](https://findevil.devpost.com) (Apr 15 – Jun 15, 2026).

[![tests](https://github.com/aksoni/sift-bench/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/aksoni/sift-bench/actions/workflows/tests.yml)

---

## Why this is interesting

Most agentic DFIR demos run an agent and show the output. SIFT-Bench does three things that most won't:

1. **A benchmark that scores analytical reasoning, not just discovery.** Ground truth includes severity-weighted findings, false-positive traps (the agent must catch and retract), and negative assertions (the agent must actively verify, not silently omit). Synthesis findings require the agent to connect process relationships, not just list them.

2. **A mandatory self-correction phase in the agent.** After investigation, the agent audits its own findings against known false-positive patterns and either CONFIRMS or RETRACTS each one with documented reasoning. Pre- and post-correction state are captured separately so the retraction itself is a scored artifact.

3. **Variance methodology.** Multiple runs scored with mean ± stdev rather than point estimates. The scorer is deterministic (verified) so the variance measured is agent variance, not measurement noise.

---

## Results

Benchmark: SANS FOR508 Stark Research Labs case SRL-2018, base-rd01 memory image. Ground truth v1.1: 14 findings (5 critical), 3 false-positive traps, 5 negative assertions.

Scored by **scorer v0.4** (LLM-as-judge semantic matching, `claude-sonnet-4-6`, verdicts cached in `scorer_cache/`):

| Run | Config | F1 | Recall | Critical (must-find) | FP traps | Negative assertions |
|-----|--------|---:|-------:|---------------------:|---------:|---------------------:|
| 1 | Baseline CLAUDE.md | 0.8704 | 0.7705 | **5/5** | 3/3 | 3/5 |
| 2 | + `dlllist` + persistence check | 0.8598 | 0.7541 | 4/5 | 2/3 | 3/5 |
| 3 | + output schema pin | 0.9204 | 0.8525 | **5/5** | 3/3 | 3/5 |
| 4 | + MCP server (hash_file + yara_scan) | 0.8909 | 0.8033 | **5/5** | 3/3 | 3/5 |

**Post-tuning baseline (N=2, runs 2+3): mean F1 = 0.890 ± 0.030, recall = 0.803 ± 0.049.** All 5 critical findings identified in runs 1 and 3. Run 4 (MCP-enabled) scored 0.8909 F1; see [`RESULTS.md`](RESULTS.md) for E1–E6 evaluation.

v0.4 numbers are lower than v0.3 (0.971 post-tuning mean) because the judge removes false credits that keyword overlap was granting — in particular, a fourth undocumented case in run 2 where the agent's DLL-profile finding was being credited against the stealth-shell finding on shared process vocabulary. The lower number is the more honest one.

See [`RESULTS.md`](RESULTS.md) for the full run-by-run breakdown, v0.3 vs v0.4 comparison, confidence-3 verdict investigation, scorer evolution (four iterations), and known limitations.

---

## Architecture

Three-phase workflow defined in [`CLAUDE.md`](CLAUDE.md):

1. **INVESTIGATE + ENRICH** — nine-step Volatility 3 methodology (psscan → pstree → cmdline → netscan → malfind → filescan → getsids → dlllist → registry/svcscan persistence check), with inline YARA scanning and file hashing via MCP tools when available.

2. **SELF-CORRECT** — evidence audit (every finding must cite tool output), methodology check, consistency check, false-positive review against known patterns. Pre-correction findings saved before any changes.

3. **REPORT** — investigative narrative (markdown), structured findings (JSON conforming to pinned schema), execution log. MITRE ATT&CK mapping, UTC timestamps.

The MCP server (`yara_scan`, `hash_file` tools) is designed to be extensible to VirusTotal, Censys, and other threat intel sources.

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
├── scorer/                      Scorer v0.4 package
│   ├── scorer.py                Matching logic + score() function
│   ├── judge.py                 LLM-as-judge call with retry + cache
│   ├── judge_cache.py           Content-addressed verdict cache
│   └── prompts/judge_v0.4.txt  Few-shot judge prompt (hash-pinned)
├── scorer_cache/
│   └── judge_verdicts.json      Cached verdicts (committed; enables no-API reruns)
├── tests/
│   └── validate_judge.py        Regression suite for the judge prompt
├── mcp_server/                  YARA + hash enrichment MCP server (week 2)
├── yara_rules/                  Detection rules (week 2)
└── cases/
    └── srl-2018/                Per-case working area
        ├── run1_analysis/       Baseline run outputs
        ├── run1_reports/
        ├── run2_analysis/       Post-tuning run outputs
        ├── run2_reports/
        ├── run3_analysis/       Schema-pinned run outputs
        └── run3_reports/
```

---

## Reproducing

**Requirements:**
- SANS SIFT Workstation (Ubuntu, x86-64) or equivalent with Volatility 3 ≥ 2.27 on PATH as `vol`
- Claude Code ≥ 2.1
- Python 3.10+ (for scorer; no external dependencies)
- A memory image to analyze (the SRL-2018 base-rd01 image used here is from the SANS FOR508 course and is not redistributable)

**Setup:**

```bash
git clone https://github.com/<your-username>/sift-bench.git
cd sift-bench

# Place your memory image at ./evidence/ (gitignored)
mkdir -p evidence
cp /path/to/memory.img evidence/

# Install the self-correction skill globally
mkdir -p ~/.claude/skills/self-correction
cp skills/self-correction/SKILL.md ~/.claude/skills/self-correction/
```

**Run the agent:**

```bash
cd cases/srl-2018  # or any case directory under cases/
claude "Analyze the memory image at ../../evidence/<image>.img following the workflow defined in CLAUDE.md. Save all outputs to ./analysis/, ./exports/, and ./reports/."
```

Expect ~17 minutes wall time on a 4-vCPU / 16 GB VM.

**Score against ground truth:**

```bash
# Requires ANTHROPIC_API_KEY on first run; subsequent runs use the committed cache
python scorer.py ground_truth/base-rd01-v1.1.json cases/srl-2018/run3_analysis/findings_post_correction.json
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

- Scorer precision is stubbed at 1.0 pending v0.5 implementation
- F011 (spsql NTUSER.DAT) is a stable miss across all three runs — methodology gap, recoverable with an additional step
- N=2 post-tuning runs; larger N would tighten the confidence interval (currently σ = 0.030 under v0.4)
- MCP server (YARA + hash enrichment) was disabled in baseline runs 1–3 to keep them comparable; Run 4 is the MCP-enabled comparison

---

## License

MIT. See [LICENSE](LICENSE).

The SANS FOR508 dataset used for the ground truth case is NOT covered by this license and is not redistributed in this repository.

---

## Acknowledgements

- SANS DFIR / FOR508 for the Stark Research Labs case dataset
- The Volatility Foundation for Volatility 3
- Anthropic for Claude Code and the Model Context Protocol
- Protocol SIFT for the baseline forensic workflow this agent extends
