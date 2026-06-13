# Dataset

Documentation for the benchmark case SIFT-Bench is evaluated against: what it is,
where it comes from, what the ground truth encodes, and what the reference agent found.
Every figure below is traceable to a committed file (`ground_truth/base-rd01-v1.1.json`,
`analysis/v05_rescoring/run6_score.json`, `RESULTS.md`).

## Primary case

**SANS FOR508 — Stark Research Labs, case SRL-2018, host `base-rd01`.**

| Property | Value | Source field |
|---|---|---|
| Case ID | `srl-2018-base-rd01` | `case_id` |
| Image file | `base-rd01-memory.img` | `image` |
| Data type | Windows 10 x64 memory capture, Build 16299 | `os`, `image_type` |
| Size | ~3 GB (3,221,225,472 bytes) | `image_size_bytes` |
| Hostname | `BASE-RD-01` | `hostname` |
| Host IP | 172.16.6.11 | `ip_address` |
| Primary user | `tdungan` | `primary_user` |
| System boot | 2018-08-30T13:51:58Z | `system_boot` |
| Capture time | 2018-09-06T18:57:17Z | `capture_time` |
| Source dataset | SANS FOR508 SRL-2018 (Stark Research Labs) | `dataset` |
| Acquisition tooling | Volatility 3 v2.27.0 (11 plugins) | `source_data` |

**Redistribution:** The memory image is **not** included in this repository. The SANS
FOR508 dataset is course material and is not redistributable. This is the SANS FOR508
SRL-2018 starter case — the common case distributed to Find Evil! entrants — so it is
data judges already have, not a private or paid dependency; it is omitted here solely to
respect SANS course-material redistribution terms. The benchmark is fully reviewable
without it — committed run outputs, the hand-authored ground truth, the cached LLM-judge
verdicts, and the unit tests reproduce all headline numbers with no image and no API key
(see [`README.md`](README.md) § "Fast review without the memory image").

## Incident summary

APT intrusion on a simulated enterprise. `BASE-RD-01` is an **RDP host reached via
lateral movement** from a previously compromised system — it is explicitly **not**
System Zero (`scenario_context`). The encoded attack:

- **`p.exe`** — malicious executable staged at `c:\windows\temp\perfmon\p.exe`, a
  network-capable C2 implant (GT F001, F013).
- **`spsql` account** — the attack runs under `spsql`, which holds **Domain Admin**
  privileges (GT F002).
- **WMI lateral movement** — `WmiPrvSE.exe` → `powershell.exe` is the entry mechanism
  onto this host (GT F003).
- **C2 channel** — to **172.16.4.10 on port 8080** (GT F004).
- **Stealth PowerShell C2 shell** — 32-bit `powershell.exe` PID 5848 with
  `-s -NoLogo -NoProfile` flags, spawning six `rundll32.exe` instances (GT F005, F006).

Network map (`network_map`): this host `172.16.6.11`; C2 `172.16.4.10`; SMB lateral
target `172.16.7.15`; RDP lateral target `172.16.4.5`.

## Ground truth

**File:** [`ground_truth/base-rd01-v1.1.json`](ground_truth/base-rd01-v1.1.json)
(hand-authored from manual Volatility 3 analysis; authored 2026-04-17, last updated
2026-05-15, with an in-file `version_history`).

- **14 findings** — 5 critical, 3 high, 3 medium, 3 low.
- **3 false-positive traps** — FP001 Outlook `dtrR` RWX pattern, FP002 McAfee updater
  RWX page (0x5070000), FP003 PowerShell .NET CLR heap RWX segments.
- **5 negative assertions** — NA001 (not System Zero), NA002 (no registry persistence),
  NA003 (Outlook `dtrR` not injection), NA004 (external IP not exfiltration), NA005
  (PowerShell RWX not injection).
- **Severity weights** — critical = 4, high = 2, medium = 1, low = 0.5. **Total weighted
  mass = 30.5** (used for weighted recall; a missed critical costs 8× a missed low).

The 14 findings deliberately span detection (criticals), a synthesis finding (F008 full
attack chain), a negative finding (F009 no registry persistence), and false-positive
discrimination (F010 CLR heap correctly classified as benign) — so the benchmark scores
analytical rigor, not just hit count.

## What the reference agent found (best run)

**Run 6** (MCP enrichment tools live, pre-flight gate verified) — scored under the
current scorer v0.5. Source: [`analysis/v05_rescoring/run6_score.json`](analysis/v05_rescoring/run6_score.json),
[`RESULTS.md`](RESULTS.md).

| Metric | Value |
|---|---|
| Weighted F1 | **0.9833** |
| Weighted recall | 0.9672 |
| Precision | 1.0 (calibrated, not stubbed — see `RESULTS.md` adversarial calibration) |
| Matched | 12 / 14 |
| Critical found | **5 / 5** |
| FP traps caught | 3 / 3 |
| Negative assertions addressed | 3 / 5 (missed NA001, NA004) |

**Misses, documented honestly (both low severity, 0.5 weight each):**
- **F011** — `spsql` NTUSER.DAT loaded in memory. **Missed in all six runs**: no
  methodology step explicitly checks loaded user hives. A genuine agent/methodology gap,
  not a scoring artifact (`RESULTS.md` § "Stable misses").
- **F014** — PowerShell C2 shell has AMSI + multiple unnamed DLLs loaded.

Full accuracy accounting — false positives, missed artifacts, the F1 metric's asymmetry,
and the evidence-integrity story — is in [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md).

## Output paths

The agent's per-run artifacts for the best run are committed at:
- [`cases/srl-2018/run6_analysis/`](cases/srl-2018/run6_analysis/) — raw tool output,
  pre/post-correction findings, execution log, MCP-tool invocation record.
- [`cases/srl-2018/run6_reports/`](cases/srl-2018/run6_reports/) — investigative
  narrative and structured findings.

Runs 1–5 are committed under the parallel `run{1..5}_analysis/` and `run{N}_reports/`
directories for the full run-by-run comparison in `RESULTS.md`.
