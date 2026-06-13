# Judge Guide

A short path to evaluating SIFT-Bench without reading the full README. **Most judges
will not have the SRL-2018 memory image** (it is a SANS FOR508 dataset, not redistributed
here), so the primary path below replays everything from committed artifacts — **no image
and no API key required.** The full agent rerun is the conditional bonus path.

Every command below was run in a clean checkout and produces the output shown.

---

## Fast review — no image needed (~3 min) — START HERE

```bash
git clone https://github.com/aksoni/sift-bench.git
cd sift-bench
pip install -r requirements.txt        # direct deps are pinned (==) to dry-run-resolved versions
```

**One command for all five checks below:** `make judge-fast` (uses only `python3` — no
`jq` needed). The explicit commands follow as the manual fallback. The `jq` filters in
steps 3–4 require `jq`; the `make` targets use `python3` instead, so they run anywhere.

**1. Score the best run against ground truth** (replays from the committed judge cache —
no `ANTHROPIC_API_KEY` needed):

```bash
python scorer.py \
  ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json
```

Expected (top of output):

```
--- Weighted F1: 0.9833 ---
    Precision (count-based): 1.0000
    Recall (severity-weighted): 0.9672
Must-find critical findings: 5/5
Findings matched: 12/14
FP traps caught: 3/3
Negative assertions addressed: 3/5
```

**2. Run the test suite** (no image, no API key):

```bash
python -m unittest discover -s tests
# → Ran 94 tests ... OK
```

**3. Trace a finding to its tools** — every finding cites the exact tool calls that
produced it. Here is the critical `p.exe` malware finding (agent ID `F01`):

```bash
jq '.findings[] | select(.id=="F01") | {id, title, status, confidence, tool_attribution, sha256: .evidence.file_hash_sha256}' \
  cases/srl-2018/run6_analysis/findings_post_correction.json
```

Shows the `windows.psscan`/`cmdline`/`getsids` chain, the `mcp__hash_file` and
`mcp__yara_scan` enrichment calls, and the recorded SHA-256 — all in `tool_attribution`.

**4. Inspect the self-correction retractions** — false positives are not silently
dropped; they stay in the array as `RETRACTED` with an evidence-based reason:

```bash
jq '.findings[] | select(.status=="RETRACTED") | {id, title, retraction_reason}' \
  cases/srl-2018/run6_analysis/findings_post_correction.json
```

Returns three: Outlook `dtrR` (F15), McAfee UpdaterUI (F16), and PowerShell .NET CLR
heap (F17) — each retracted with the byte-signature evidence that proves it benign.

**5. Confirm the MCP enrichment gate** was verified live before the run:

```bash
cat cases/srl-2018/run6_analysis/mcp_verification.txt
```

> All five steps replay from committed artifacts (`scorer_cache/judge_verdicts.json`).
> No memory image and no API key are required. This was confirmed from a clean
> `python:3.12-slim` container on 2026-06-09 — transcript:
> `analysis/clean-vm-dryrun-2026-06-09.log`.

---

## Full reproduction — only if you have the SRL-2018 image (~17 min)

The SRL-2018 `base-rd01` memory image is a **SANS FOR508 course dataset and is not
redistributed in this repository.** **If** you have access to it, you can reproduce the
full agent run end-to-end. (You do not need this to evaluate the project — the fast
review above covers all committed results.)

Requirements: SANS SIFT Workstation, Claude Code, the image placed at `./evidence/`, and
`ANTHROPIC_API_KEY` (needed only for *fresh* judge verdicts; cached scoring needs none).

```bash
mkdir -p evidence && cp /path/to/base-rd01-memory.img evidence/
mkdir -p ~/.claude/skills/self-correction
cp skills/self-correction/SKILL.md ~/.claude/skills/self-correction/

cd cases/srl-2018
claude "Analyze the memory image at ../../evidence/base-rd01-memory.img following the workflow defined in CLAUDE.md. Save all outputs to ./analysis/, ./exports/, and ./reports/."
# ~17 min wall time on a 4-vCPU / 16 GB VM; then re-run the scorer from the Fast review.
```

The three-phase workflow (Investigate+Enrich → Self-Correct → Report) is defined in
`cases/srl-2018/CLAUDE.md`.

---

## What to inspect, by evaluation dimension

Agent artifacts are listed first for the execution/accuracy dimensions; the benchmark is
the validation layer. (Only "Criterion 4 — evidence integrity" is named explicitly in the
hackathon brief; the other rows are descriptive.)

| Dimension | Primary artifact(s) | What it shows |
|---|---|---|
| Autonomous execution | [`cases/srl-2018/run6_reports/investigative_narrative.md`](cases/srl-2018/run6_reports/investigative_narrative.md), [`cases/srl-2018/run6_analysis/execution_log.json`](cases/srl-2018/run6_analysis/execution_log.json) | The agent's end-to-end run: narrative + per-step tool log |
| IR accuracy | [`cases/srl-2018/run6_analysis/findings_post_correction.json`](cases/srl-2018/run6_analysis/findings_post_correction.json), [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md) | The findings themselves + honest accuracy accounting (FPs, misses) |
| Self-correction | `findings_pre_correction.json` → `findings_post_correction.json` (same dir) | Live retraction of the three FP traps; pre/post diff |
| **Evidence integrity (Criterion 4)** | [`ARCHITECTURE.md`](ARCHITECTURE.md), [`tool_executor.py`](tool_executor.py) | Prompt-based vs. architectural guardrails; the Run 4 bypass as a disclosed failure mode |
| Benchmark / scoring | [`analysis/v05_rescoring/run6_score.json`](analysis/v05_rescoring/run6_score.json), [`scorer/`](scorer/), [`RESULTS.md`](RESULTS.md) | The LLM-as-judge scorer and full run-by-run results |
| Dataset & ground truth | [`DATASET.md`](DATASET.md), [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json) | What was tested against; the hand-authored 14-finding ground truth |
| Reproducibility | [`analysis/clean-vm-dryrun-2026-06-09.log`](analysis/clean-vm-dryrun-2026-06-09.log), [`requirements.txt`](requirements.txt) | Clean-container replay; pinned dependencies |
| Token / cost accounting | [`cases/srl-2018/session_transcripts/token_usage.json`](cases/srl-2018/session_transcripts/token_usage.json) | Per-run token totals (Run 4/5 transcripts committed; Run 6 transcript not retained) |

For the project narrative (what it does, how it's built, the scorer-evolution and
MCP-integration arcs), see [`README.md`](README.md) and [`RESULTS.md`](RESULTS.md).
