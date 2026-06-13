# Architecture — SIFT-Bench

> **Reviewer-facing deliverable (submission component 3).** This document names the
> architectural pattern(s), draws the system with its **trust boundaries** marked, and — the
> Criterion-4 requirement — **separates prompt-based guardrails (the model can ignore them) from
> architectural guardrails (the model cannot bypass them).** Where a boundary is *not* yet
> architecturally enforced, it says so. The Run 4 failure-mode framing here matches
> [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md).

---

## Architectural pattern(s)

SIFT-Bench is a **hybrid of three** of the hackathon's named approaches:

1. **Direct Agent Extension** — Claude Code runs the three-phase DFIR workflow
   (`CLAUDE.md`), driving Volatility 3 and the enrichment tools. No custom agent loop.
2. **Custom MCP Server** — `sift-bench-enrichment` exposes two typed enrichment tools
   (`hash_file`, `yara_scan`) over stdio, replacing ad-hoc inline shell with an attributable
   surface.
3. **Accuracy Benchmarking Framework** — hand-authored ground truth + an LLM-as-judge scorer
   with content-addressed cached verdicts evaluates the agent's output independently of the
   agent loop.

The benchmark is the contribution; the agent is its reference implementation.

---

## System diagram

> **Rendered version: [`docs/architecture.svg`](docs/architecture.svg)** — a faithful visual
> transcription of the ASCII diagram below (same content, same caveats, including the trust
> boundaries, the `«base»`/`«ext»` provenance tags, and the Run 4 honesty markers).

```
LEGEND
  [P] prompt-based guardrail   — enforced by instruction; the model CAN ignore it
  [A] architectural guardrail  — enforced by construction; the model CANNOT bypass it
  [*] mixed boundary           — the typed surface is [A]; routing to it is [P]
  «base» inherited from Protocol SIFT (teamdfir installer)    «ext» my authorship
  ═════  trust boundary        "(NOT in Run 1-6 path)" = forward-looking guardrail

  ┌───────────────────────────────────────────────────────────────────────────┐
  │  EVIDENCE    base-rd01-memory.img    (SANS FOR508 SRL-2018)                 │
  └───────────────────────────────────────────────────────────────────────────┘
  ═════════════════ TRUST BOUNDARY 1 — EVIDENCE READ-ONLY [A] ══════════════════
        reads only ▼   no tool writes to the image, /cases/, /mnt/, …/evidence/
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  AGENT — Direct Agent Extension (Claude Code)                               │
  │                                                                             │
  │  Config  «base» ~/.claude/CLAUDE.md  global DFIR orchestrator               │
  │          «base» 5 skills: memory-analysis · plaso-timeline · sleuthkit ·    │
  │                           windows-artifacts · yara-hunting                  │
  │          «ext»  project CLAUDE.md  (3 phases, tool prohibitions)            │
  │          «ext»  self-correction skill                                       │
  │                                                                             │
  │  Phase 1  INVESTIGATE + ENRICH                                              │
  │     ├─ Volatility 3 plugins  (psscan → pstree → … → svcscan)                │
  │     └─ enrichment → SHOULD route to MCP                                      │
  │          [P] CLAUDE.md prohibits inline hash/YARA   (← bypassed in Run 4)   │
  │  Phase 2  SELF-CORRECT                                                       │
  │     [P] evidence-audit clause (cite tool output or retract)                 │
  │     [P] status model: CONFIRMED / UNCONFIRMED / RETRACTED                    │
  │          └─ the "backed by evidence" part is enforced downstream by the      │
  │             validator [A] — see scorer box                                   │
  │  Phase 3  REPORT → findings.json · narrative · execution_log.json           │
  └───────────────────────────────────────────────────────────────────────────┘
        enrichment ▼  (routing here is [P], not [A] — an inline path still exists)
  ═════════════════ TRUST BOUNDARY 2 — MCP ENRICHMENT [*] ══════════════════════
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  «ext»  MCP SERVER — sift-bench-enrichment (stdio)            [A] surface   │
  │     hash_file(path) → md5·sha1·sha256·size    yara_scan(t, r) → matches      │
  │     typed args, no shell escape; every call attributable in                 │
  │     tool_attribution — which is what made the Run 4 bypass DETECTABLE.       │
  │     NOT the exclusive enrichment path: inline shell remains available, so    │
  │     routing through the server is prompt-enforced [P], not architectural.    │
  └───────────────────────────────────────────────────────────────────────────┘
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  «ext»  tool_executor.py    [A]    (NOT in Run 1-6 path)                    │
  │     allowlist · shell=False · realpath evidence-dir write-block ·            │
  │     output-flag inspection · JSONL audit log                                │
  │     → enforces the EVIDENCE-READ-ONLY + SAFE-SHELL boundary (blocks rm /      │
  │       curl / writes into evidence). Does NOT force MCP routing — python3      │
  │       and the hash utils are on its allowlist — so it would NOT, by itself,   │
  │       have blocked the Run 4 inline-enrichment bypass.                        │
  └───────────────────────────────────────────────────────────────────────────┘
        agent output ▼  (findings.json)
  ════════════ TRUST BOUNDARY 3 — EVALUATION (separate from the agent loop) ═════
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  «ext»  BENCHMARK / SCORER — Accuracy Benchmarking Framework                │
  │     validate_findings.py  [A] — enforces the [P] status model:              │
  │            ▼                    CONFIRMED ⇒ tool_attribution non-empty        │
  │            ▼   (a CONFIRMED finding with no evidence is rejected here — the   │
  │                same shape as the Tier-A adversarial fabrications)            │
  │     scorer.py — LLM-as-judge match + evidence-traceability precision          │
  │            ▼   verdicts ⇄ content-addressed cache [A]  (bit-identical replay; │
  │                no API key needed)                                            │
  │     weighted F1 · recall · precision · FP-trap · negative-assertion ·         │
  │     methodology-coverage · self-correction-effectiveness                    │
  │     ground truth v1.1   (authored before any agent run)                     │
  └───────────────────────────────────────────────────────────────────────────┘
```

---

## The provenance boundary — inherited vs. built

The agent box above straddles a trust/authorship line that a reviewer should see explicitly. It
is **not all original work**, and the diagram says so with `«base»` / `«ext»` tags.

| Region | Origin | Components |
|---|---|---|
| **`«base»` Protocol SIFT** | Installed via the `teamdfir/protocol-sift` installer (not my authorship) | Global `~/.claude/CLAUDE.md` DFIR orchestrator; 5 base skills: memory-analysis, plaso-timeline, sleuthkit, windows-artifacts, yara-hunting |
| **`«ext»` Extension layer** | My authorship | Self-correction protocol/skill; the MCP enrichment server; the benchmark / scorer / LLM-judge + cache; ground truth v1.1; `tool_executor.py` |

Everything that makes this a *self-correcting, benchmark-scored* agent — the self-correction
loop, the typed enrichment surface, and the entire evaluation half of the diagram — is in the
extension layer. The base provides the DFIR tool-routing scaffold it runs on.

---

## Guardrails — prompt-based vs. architectural

This is the Criterion-4 distinction, and it is the most important thing in this document. The two
kinds of guardrail are **not** interchangeable: one is a request, the other is a wall.

### Prompt-based guardrails — `[P]` (the model can ignore them)

Enforced only by instruction in `CLAUDE.md`. They shape behavior when the model cooperates; they
do nothing when it doesn't.

| Guardrail | Where | What it asks |
|---|---|---|
| Inline-tool prohibition (enrichment routing) | project `CLAUDE.md` | Use the MCP tools for hash/YARA; do not use `sha256sum`/`hashlib`/`yara.compile()` |
| Self-correction audit clause | Phase 2 | Every finding must cite specific tool output or be retracted |
| Evidence bar for malware-class claims | Phase 2 | Confirm malware only with MCP-attributed hash/YARA, else mark UNCONFIRMED |
| Status model | schema | Assign CONFIRMED / UNCONFIRMED / RETRACTED honestly |

### Architectural guardrails — `[A]` (the model cannot bypass them)

Enforced by construction. They hold regardless of what the model "decides," because the model is
not in the enforcement path.

| Guardrail | Where | Why it can't be bypassed |
|---|---|---|
| Typed enrichment surface (*when used*) | MCP server | A call to the server takes typed args with no shell to escape into, and every call is attributable in `tool_attribution` — which is what made the Run 4 bypass *detectable*. (Note: the server is **not** the exclusive enrichment path, so *routing* to it is `[P]`, not `[A]` — see "still prompt-based" below.) |
| Subprocess guardrail | `tool_executor.py` | Stem allowlist; `shell=False` enforced unconditionally (caller cannot re-enable); `realpath`-based evidence-dir write-block (defeats symlink bypass); output-flag inspection. 19 tests incl. symlink-bypass and shell-metacharacter-as-literal. Enforces the **evidence-read-only / safe-shell** boundary. |
| Findings validator | `scorer/validate_findings.py` | Deterministic pre-flight schema gate; a CONFIRMED finding with empty `tool_attribution` is rejected before it can be scored — this is what enforces that the `[P]` status model is backed by evidence |
| Replayable verdicts | content-addressed cache | Judge verdicts keyed on content hashes → bit-identical re-score, auditable by any reviewer without an API key |

### Where enforcement is still prompt-based (the honest scope)

One boundary is **not** architecturally enforced, and stating that plainly is the stronger
Criterion-4 answer (the brief: *if you're using prompt-based restrictions rather than architectural
enforcement, document what happens when the model ignores the restriction*).

**Enrichment routing** — using the MCP tools instead of computing hashes/YARA inline — is governed
by a `CLAUDE.md` prohibition, i.e. it is **prompt-based `[P]`**. The agent retains an inline path:
`python3`, `sha256sum`, and yara-python are all available, and `python3`/`sha256sum` are even on
the `tool_executor` allowlist. So neither the MCP server nor `tool_executor` *forces* the agent to
route enrichment through the typed surface. The enforcement timeline is:

- **Run 4 — the prompt-based control failed.** The agent computed a SHA-256 and ran
  `python3 yara.compile(...).match('8260.p.exe.0x400000.dmp')` inline, bypassing the MCP server.
- **Detection — architectural.** The typed MCP surface made the bypass visible: the inline path
  left no `mcp__hash_file` / `mcp__yara_scan` in `tool_attribution`, so scoring caught it.
- **Run 6 — prevention, but still prompt-based.** Strengthened `CLAUDE.md` prohibitions plus a
  pre-flight gate produced the intended routing. This works, but it is a *better prompt*, not a
  wall.
- **Architectural closure — not built.** Forcing MCP as the *only* enrichment route (removing the
  inline path) is honest future work, scoped out of this submission.

So the truthful Criterion-4 position — the same thesis stated in [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md):
**evidence integrity is architecturally enforced; enrichment routing is prompt-enforced**.
Evidence integrity is held by `tool_executor`, the typed MCP surface, the validator, and the cache;
enrichment routing has a documented failure (Run 4), a working prompt-level mitigation (Run 6), and
a named architectural fix that is not yet built.

### Why the distinction is the centerpiece: the Run 4 bypass

The two layers exist because the first one **demonstrably failed**, and the failure was disclosed
rather than buried (the hackathon brief: *if you found failure modes, document them — that's
signal*).

Through Run 3, enrichment was governed only by the **prompt-based** prohibition: `CLAUDE.md` told
the agent to route hashing/YARA through the MCP server. Run 4 was the first run with the server
live. The agent produced real enrichment — a SHA-256 and a `Meterpreter_NamedPipe_Transport` YARA
match — but **bypassed the MCP server**, computing both inline
(`python3 yara.compile(...).match('8260.p.exe.0x400000.dmp')`, no `mcp__hash_file`/`mcp__yara_scan`
in `tool_attribution`). A prompt that asks for a behavior is not a control that enforces it.

The response splits cleanly by enforcement type, and naming which is which is the point:

- **Detection** came from the typed MCP surface — the inline-vs-MCP distinction is visible in
  `tool_attribution`, so the bypass was caught at scoring and disclosed in `RESULTS.md`
  (R4-E1/E2/E3 all DEVIATION).
- **Prevention** in Run 6 came from strengthened **prompt-based** prohibitions plus the gate —
  still a prompt-level control, now demonstrated working.
- **Architectural closure** of the routing path (making MCP the only route) is named future work.
- `tool_executor.py` hardens a *related but distinct* boundary — evidence-read-only / safe-shell —
  and does **not**, by itself, force routing (it allowlists `python3` and the hash utilities).

Full narrative in [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md).

---

## Trust boundaries (the three marked on the diagram)

1. **Evidence read-only `[A]`** — the memory image is consumed read-only. No tool in any run
   wrote back to the image, `/cases/`, `/mnt/`, `/media/`, or any `…/evidence/` path. Going
   forward, `tool_executor.py` enforces this by construction; in Runs 1-6 it held because the
   analysis tools (Volatility 3) open the image read-only.
2. **MCP enrichment `[*]`** — the MCP tools expose a typed surface `[A]` (typed args, no shell
   escape, every call attributable). But that surface is **not the exclusive enrichment path**, so
   *routing* through it is prompt-enforced `[P]`, not architectural. This is the boundary the Run 4
   agent bypassed; Run 6 mitigated it by stronger prompting; architectural closure is future work.
3. **Evaluation `[A]`** — scoring is a separate stage from the agent loop: agent output →
   deterministic validator → LLM-judge scorer → metrics. The thing being measured cannot
   influence the measurement; verdicts are cached and replayable. The validator also enforces the
   `[P]` status model (a CONFIRMED finding with no `tool_attribution` is rejected) — the same check
   that catches the Tier-A artifact-free fabrications in the adversarial calibration.

---

## Honest scope note

`tool_executor.py` is a **forward-looking architectural guardrail** — implemented and tested (19
tests), but **not retroactively wrapped around Runs 1-6** (its file header states this). It is
marked `(NOT in Run 1-6 path)` in the diagram for two reasons:

1. **It did not gate the historical runs.** Wrapping it around Runs 1-6 after the fact would alter
   them and invalidate the variance methodology, so the historical results stand as produced and
   the executor is the control going forward.
2. **It enforces evidence integrity, not enrichment routing.** It blocks non-allowlisted/
   destructive commands and writes into the evidence image — but `python3` and the hashing
   utilities are on its allowlist, so it would **not**, by itself, have blocked the Run 4
   inline-enrichment bypass. Attributing the routing fix to it would be an overclaim; the routing
   control is prompt-based (above).

Same disclosure discipline as the rest of the project: claim only what the artifacts support — a
claim of enforcement is checked against what the code actually enforces.

---

*Extends the component layout of the README `## Architecture` diagram; adds the pattern names,
provenance boundary, trust boundaries, and the prompt-vs-architectural guardrail distinction it
lacked. Draft for review.*
