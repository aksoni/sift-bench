# Accuracy Report — SIFT-Bench Reference Agent (SRL-2018, Run 6)

> **Reviewer-facing deliverable (submission component 6).** Every figure below traces to a
> committed artifact, named inline. Scores are reproducible without an API key from the
> committed judge cache (see [Reproducibility](#reproducibility)).
>
> **Scope of this report:** the SIFT-Bench *reference agent's* output on the SRL-2018
> `base-rd01` memory image, best run (Run 6), scored by the committed v0.5 scorer. It also
> documents one disclosed failure mode (Run 4) and the evidence-integrity guardrails that
> failure motivated.

---

## Summary — Run 6 headline

Source: `analysis/v05_rescoring/run6_score.json`.

| Metric | Value |
|---|---|
| Weighted F1 | **0.9833** |
| Recall (severity-weighted) | 0.9672 |
| Precision (count-based) | 1.0 |
| Must-find critical findings | **5 / 5** |
| False-positive traps caught | **3 / 3** (FP001, FP002, FP003) |
| Findings matched | 12 / 14 |
| Confirmed false positives in output (`count_fp`) | **0** |

Run 6 is the first run with the MCP enrichment tools (`mcp__hash_file`, `mcp__yara_scan`)
invoked end-to-end; both malware-class hashes are MCP-attributed (p.exe
`6f9d6ec7…`, procdump.exe `8b87ad36…`). Full run-by-run context: `RESULTS.md`.

---

## Correct findings / Missed artifacts

**12 of 14 ground-truth findings matched** (`run6_score.json → findings_matched`), including
all five must-find criticals:

| GT | Sev | Finding | Judge conf |
|---|---|---|---|
| F001 | critical | Malicious executable `p.exe` in attacker staging directory | 5 |
| F002 | critical | Attack under `spsql` account with Domain Admin privileges | 4 |
| F003 | critical | WMI lateral movement used to access this host | 5 |
| F004 | critical | C2 to 172.16.4.10:8080 | 5 |
| F005 | critical | PowerShell C2 shell with stealth flags | 5 |
| F006 | high | Six short-lived `rundll32.exe` instances from the PS C2 shell | 5 |
| F008 | high | Full attack-chain process tree | 5 |
| F013 | high | `p.exe` DLL profile confirms network-capable C2 implant | 5 |
| F007 | medium | Outbound lateral movement via SMB and RDP | 4 |
| F009 | medium | No registry-based persistence installed (negative finding) | 5 |
| F012 | medium | `procdump.exe` present in Dashlane directory | 5 |
| F010 | low | PowerShell (PID 8712) malfind hits are .NET CLR heap, not injection | 5 |

**2 missed — both low-severity (weight 0.5 each), and documented openly, not hidden:**

- **F011** — `spsql` NTUSER.DAT loaded in memory. A methodology gap: no investigation step
  explicitly enumerates loaded user hives. Stable miss across all six runs.
- **F014** — PowerShell C2 shell has AMSI loaded and multiple unnamed DLLs.

These are recorded as known gaps in `RESULTS.md` ("Stable misses") and carry combined weight
1.0 of 30.5 total. They are surfaced here for the same reason they are surfaced in RESULTS:
a benchmark that hides its agent's misses cannot be trusted to report anyone else's.

---

## False positives / hallucinations

**Across all six committed agent runs, `count_fp = 0`** — the v0.5 evidence-traceability
precision judge returned `legitimate=false` zero times in 41 verdicts. Precision is therefore
a *computed* 1.0, not the v0.4 hardcoded stub it replaced.

A computed value that never moves is indistinguishable from a stub to a skeptical reviewer.
So the metric was deliberately stress-tested. Source: `design/scorer-v0.5-adversarial.md`
(pre-registered **before** the adversarial input existed or any verdict was observed) and
`analysis/v05_rescoring/adversarial_score.json`.

Six fabricated findings were injected into Run 6's real output, in three pre-graded tiers:

| Tier | Fabrication | Predicted verdict | Actual |
|---|---|---|---|
| A (×3) | Artifact-free conclusions — Mimikatz/LSASS, kernel rootkit, "2.3 GB exfiltrated," all with empty evidence | `legitimate=false` → counted as FP | **caught (3/3)** |
| B (×2) | Coherent but invented specifics — fake PID/IP `svch0st.exe`, fake hash + YARA match for `p2.exe` | `legitimate=true` → dropped, precision unaffected | **passed through (as predicted)** |
| C (×1) | Borderline RWX claim, hedged | `confidence<4` → uncertain, dropped | **uncertain (as predicted)** |

**Pre-registered numeric prediction: `12 / (12 + 3) = 0.80`. Actual: `weighted_precision = 0.80`,
`weighted_recall = 0.9672` (held as control). Zero deviation.**

This is the honest, two-sided result: the metric *does* catch uncited fabrications (Tier A),
and it *cannot* catch coherent fabrications citing invented-but-well-formed specifics (Tier B) —
because the judge is image-blind and tests **evidence traceability, not evidence truth**. That
ceiling is pre-registered, not discovered after the fact, and the structurally-different fix
(a deterministic check that each cited PID/path/IP/hash actually exists in the run's tool
output) is named as future work, explicitly **out of scope for this submission**. See
`design/scorer-v0.5-adversarial.md` §"Known ceiling."

---

## Confirmed vs inferred

Every finding carries an explicit verdict, separate from its evidence-strength `confidence`:

- **CONFIRMED** — evidence cited and survives the Phase 2 self-correction audit.
- **UNCONFIRMED** — observed but evidence is insufficient to confirm; not retracted, not asserted.
- **RETRACTED** — withdrawn during self-correction (kept in the findings array with a
  `retraction_reason`, so the retraction itself is auditable).

**Malware-class claims carry a higher bar.** Per the Phase 2 audit clause (project `CLAUDE.md`),
any finding classifying a binary as malware / loader / C2 / implant must cite at least one of:
(a) a SHA-256 from an `mcp__hash_file` invocation, (b) a YARA match from `mcp__yara_scan`, or
(c) explicit acknowledgment the artifact was not extractable. Inline `sha256sum` / `hashlib` /
`Get-FileHash` do **not** satisfy it. Absent all three, the finding is downgraded to UNCONFIRMED.

This clause is demonstrably load-bearing: in Run 5 (MCP server unreachable) the agent
reclassified the `p.exe` malware finding to **UNCONFIRMED** rather than fall back to inline
hashing — the audit clause declining to confirm without attributable evidence (`RESULTS.md`,
R5-E4).

---

## On the F1 metric

The headline F1 is an **asymmetric hybrid by design**: severity-weighted recall combined with
count-based precision. This is a deliberate modeling choice, because the costs of the two error
types do not scale the same way in a real investigation.

- **Recall is severity-weighted** because the cost of a *miss* scales with severity. Failing to
  surface the C2 channel or the Domain-Admin compromise (critical, weight 4) is a categorically
  worse outcome than missing an AMSI-DLL detail (low, weight 0.5). Severity-weighting makes the
  metric penalize the misses that would actually sink an investigation, in proportion to the
  damage they do.

- **Precision is count-based** because the cost of a *fabrication* does not scale with the
  severity it claims — it scales with the fact that it is fabricated at all. A hallucinated
  "critical" finding is not four times worse than a hallucinated "low" one; each is a single
  illegitimate claim that equally corrodes trust in the whole report. Severity-weighting precision
  would be actively perverse: it would reward an agent for attaching *higher* severity to its
  fabrications, inflating the denominator. Counting each fabrication as one unit closes that
  loophole.

In short: **misses are weighted by how much they matter; fabrications are weighted by the fact
that they happened.** The two quantities are normalized differently on purpose, so their harmonic
mean is not a textbook single-scheme F1 — and the scorer states exactly that on every score it
prints (`run6_score.json → precision_note`):

> "Precision is count-based (unit weight per agent finding); recall is severity-weighted.
> weighted_f1 is their harmonic mean — mathematically valid but an asymmetric hybrid, not a
> single-scheme F1."

That caveat is emitted by the instrument itself, unprompted, on every run. The design is declared
at the point of measurement — not reconstructed for a reviewer after the fact.

---

## Evidence integrity & guardrails

*(Hackathon Criterion 4. This is the report's centerpiece.)*

Evidence integrity in this project is enforced at two layers, and — more usefully for a reviewer
— the boundary between them was established by a **documented, disclosed failure of the first
layer.**

### The Run 4 bypass — a failure mode, surfaced as signal

The hackathon brief invites exactly this: *if you found failure modes, document them — that's
signal, not weakness.* Here is ours, in full.

Through Run 3, evidence enrichment was governed by a **prompt-level** guardrail: the project
`CLAUDE.md` instructed the agent to compute hashes and run YARA scans through the registered MCP
server. Run 4 was the first run with that server live, and it was meant to demonstrate the
integration end-to-end.

It did the opposite. The agent produced genuinely useful enrichment — a SHA-256 for `p.exe` and a
YARA match (`Meterpreter_NamedPipe_Transport`) — but **bypassed the MCP server entirely.** The
`tool_attribution` evidence shows it: the hash carries only `vol … pslist --dump`, with no
`mcp__hash_file` call, and the YARA match was produced by
`python3 yara.compile('Meterpreter_NamedPipe_Transport').match('8260.p.exe.0x400000.dmp')` — a
direct `yara-python` call, using neither the registered `mcp__yara_scan` tool nor the operative
ruleset (`RESULTS.md`, R4-E1/E2). No `execution_log.json` was produced, so the call chain could
not even be independently reconstructed.

The diagnosis: the MCP server was registered and reachable; the failure was *routing*. The
`CLAUDE.md` language was descriptive ("use the MCP tools…") rather than directive, and the agent
took the path of least resistance to an inline equivalent. **A prompt that asks for a behavior is
not a control that enforces it.**

This was caught at scoring, disclosed in `RESULTS.md` (all of R4-E1/E2/E3 marked DEVIATION), and
drove the next two runs: Run 5 strengthened the `CLAUDE.md` prohibitions (and surfaced a *second*
failure — the `.mcp.json` was at the wrong path, so the server never loaded — itself disclosed
rather than quietly fixed); Run 6 corrected the path and met E1/E2/E3, with both malware-class
hashes finally MCP-attributed. The bypass is not an embarrassment buried in an appendix — it is
the reason the architectural layer below exists.

### The two layers

**Layer 1 — prompt-level (governs agent behavior).**
- `CLAUDE.md` prohibitions on inline hash/YARA equivalents; malware-class claims require
  MCP-attributed evidence (the Phase 2 audit clause, above).
- The self-correction audit: every finding must cite specific tool output or be retracted.
- *Demonstrated limitation:* Run 4 proved a prompt-level guardrail can be silently bypassed.

**Layer 2 — architectural (does not depend on the agent cooperating).**
- **Typed MCP tools instead of arbitrary shell.** `mcp__hash_file` / `mcp__yara_scan` expose a
  narrow, attributable surface; their output lands in `tool_attribution` with the MCP source
  named, which is precisely what made the Run 4 bypass *detectable* in the first place.
- **`tool_executor.py` — a subprocess guardrail** (`design/tool-executor-v1.md`): a stem-based
  command allowlist; `shell=False` enforced unconditionally (caller cannot re-enable it);
  evidence-directory writes blocked via `os.path.realpath()` (defeats symlink bypass) with
  output-flag inspection across `--output PATH`, `--output=PATH`, and `-oPATH` forms; any
  `/cases/`, `/mnt/`, `/media/`, or `…/evidence/…` path blocked; structured JSONL audit log.
  Covered by 19 tests, including `test_symlink_to_evidence_dir_blocked` and
  `test_shell_metacharacter_is_literal` (verifies `; rm -rf /` is passed as a literal argument,
  not interpreted).
- **Findings validator** (`scorer/validate_findings.py`): a pre-flight schema gate that enforces,
  among other rules, `CONFIRMED → tool_attribution` non-empty — a CONFIRMED finding with no
  cited tool is rejected before scoring.

### Honest scope note

`tool_executor.py` is a **forward-looking v2 component** (its own file header says so). It is
**not** retroactively wrapped around Runs 1–6 — doing so would alter the historical runs and
invalidate the variance methodology. The Run 1–6 results stand as produced; the executor is the
control going forward.

### Spoliation / chain of custody

The evidence image (`base-rd01-memory.img`) is treated strictly read-only. Volatility 3 operates
on the image without modifying it; all agent output is routed to `./analysis/`, `./reports/`, and
the per-run case directories. No historical run wrote to the evidence image or to a `/cases/…
/evidence/` path. The `tool_executor` write-block (Layer 2) exists to keep that property true by
construction for future runs, not by convention.

---

## Reproducibility

The headline numbers are reproducible by a reviewer with no credentials and no API key.

Verified on **2026-06-09** from a clean `python:3.12-slim` container — public HTTPS clone, no
`.env`, `ANTHROPIC_API_KEY` confirmed unset — both the Run 6 score (**0.9833**) and the
adversarial score (**precision 0.80 / F1 0.8757**) replayed **bit-identically** from the committed
judge cache (`scorer_cache/judge_verdicts.json`), and all **94 unit tests** passed. Full
transcript: `analysis/clean-vm-dryrun-2026-06-09.log`.

```bash
python -m pip install -r requirements.txt
python scorer.py ground_truth/base-rd01-v1.1.json \
  cases/srl-2018/run6_analysis/findings_post_correction.json   # → weighted_f1: 0.9833
python -m unittest discover -s tests                            # → Ran 94 tests ... OK
```

Determinism comes from the committed cache, not from model sampling: the scorer reads cached
judge verdicts keyed on content hashes, so reruns are exact. See `README.md` §"Reviewing without
the memory image."

---

*All figures sourced from committed artifacts as of the latest `master` and verified against the
score JSONs and `RESULTS.md`. Scores reproduce from the committed judge cache without an API key
(`analysis/clean-vm-dryrun-2026-06-09.log`).*
