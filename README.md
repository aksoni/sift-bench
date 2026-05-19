# SIFT-Bench

**A benchmark and evaluation framework for autonomous DFIR agents, with a self-correcting reference implementation built on Claude Code + SIFT Workstation + Volatility 3.**

SIFT-Bench measures evidence quality, false-positive handling, negative assertion verification, and analytical rigor — not just IOC extraction. Includes a hand-authored ground truth, a deterministic standalone scorer, and a custom MCP server for YARA and hash enrichment.

Solo submission to the [Find Evil! hackathon](https://findevil.devpost.com) (Apr 15 – Jun 15, 2026).

---

## Why this is interesting

Most agentic DFIR demos run an agent and show the output. SIFT-Bench does three things that most won't:

1. **A benchmark that scores analytical reasoning, not just discovery.** Ground truth includes severity-weighted findings, false-positive traps (the agent must catch and retract), and negative assertions (the agent must actively verify, not silently omit). Synthesis findings require the agent to connect process relationships, not just list them.

2. **A mandatory self-correction phase in the agent.** After investigation, the agent audits its own findings against known false-positive patterns and either CONFIRMS or RETRACTS each one with documented reasoning. Pre- and post-correction state are captured separately so the retraction itself is a scored artifact.

3. **Variance methodology.** Multiple runs scored with mean ± stdev rather than point estimates. The scorer is deterministic (verified) so the variance measured is agent variance, not measurement noise.

---

## Results

Benchmark: SANS FOR508 Stark Research Labs case SRL-2018, base-rd01 memory image. Ground truth v1.1: 14 findings (5 critical), 3 false-positive traps, 5 negative assertions.

| Run | Config | F1 | Recall | Critical (must-find) | FP traps | Negative assertions |
|-----|--------|---:|-------:|---------------------:|---------:|---------------------:|
| 1 | Baseline CLAUDE.md | 0.870 | 0.771 | **5/5** | 3/3 | 3/5 |
| 2 | + `dlllist` + persistence check | 0.975 | 0.951 | **5/5** | 2/3 | 3/5 |
| 3 | + output schema pin | 0.966 | 0.934 | **5/5** | 3/3 | 3/5 |

**Post-tuning (N=2): mean F1 = 0.971 ± 0.006, recall = 0.943 ± 0.012.** All 5 critical findings identified in every run.

**Tuning impact:** adding two methodology steps to CLAUDE.md improved weighted F1 by **+0.105** and recall by **+0.180** between runs 1 and 2. One false-positive catch regressed in run 2 (McAfee UpdaterUI) but recovered in run 3 — task variance rather than systematic failure. This is the kind of feedback-loop signal a tuned detection system should expose, and we document it rather than hide it.

See [`RESULTS.md`](RESULTS.md) for the full run-by-run breakdown, scorer evolution (three iterations), manual cross-check of run 3, stable-vs-unstable behavior analysis, and known limitations.

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
├── scorer.py                    Deterministic standalone benchmark scorer (no deps)
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
python scorer.py ground_truth/base-rd01-v1.1.json cases/srl-2018/run3_analysis/findings_post_correction.json
```

Scorer is deterministic — repeated invocations on identical input produce identical scores.

---

## Methodology notes

- **Ground truth was authored before any agent runs**, with documented version history. v1.1 changes (F010 reclassification from "suspicious" to false positive, addition of FP003 and NA005, expansion of methodology checklist) are recorded in the ground truth file's `version_history` field.

- **F010 reclassification** was resolved via hexdump evidence review confirming the 0xFFEEFFEE .NET CLR heap signature, not AI inference.

- **The scorer has been iterated three times** during development as failure modes were discovered through use: v0.1 → v0.2 fixed double-matching, v0.2 → v0.3 fixed hash-seed nondeterminism, v0.3 → v0.4 (week 3) will replace keyword overlap with LLM-as-judge for principled semantic matching. See [`RESULTS.md`](RESULTS.md) for the full evolution.

- **Variance across runs is treated as signal, not noise.** Stable behaviors (all 5 critical findings, Outlook/CLR retractions, core attack chain) form the backbone of the demo. Unstable behaviors (which exact FPs get caught run-to-run) are reported with mean ± stdev. See [`RESULTS.md`](RESULTS.md) for the full breakdown.

---

## Known limitations

- Scorer precision is stubbed at 1.0 pending LLM-as-judge implementation (week 3)
- Keyword-overlap matching can confuse semantically distinct findings that share vocabulary; LLM-as-judge will resolve
- F011 (spsql NTUSER.DAT) is a stable miss across all three runs — methodology gap, recoverable with an additional step in a future revision
- N=2 post-tuning runs; larger N would tighten the confidence interval (currently σ = 0.006)
- MCP server (YARA + hash enrichment) currently disabled in baseline runs to keep them comparable to runs without enrichment infrastructure

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
