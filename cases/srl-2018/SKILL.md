# Skill: Self-Correction Protocol

## Overview

This skill defines the mandatory self-correction phase that runs after the investigation.
The purpose is to catch hallucinations, false positives, missed steps, and internal
contradictions before producing the final report.

**This phase is not optional. Skip it and the report is untrustworthy.**

---

## Pre-Correction Snapshot

Before making any corrections, save your current findings:

```bash
# Save pre-correction state for later diff
cat > ./analysis/findings_pre_correction.json << 'SNAPSHOT'
[paste your current findings as JSON array here]
SNAPSHOT
```

This snapshot is critical — it's how we measure self-correction effectiveness.

---

## Self-Correction Steps

### Step 1: EVIDENCE AUDIT

For every finding you plan to include in the report:

1. Identify the specific tool command that produced the evidence
2. Locate the raw output in `./analysis/` that supports the claim
3. Verify the output actually says what you think it says

**If you cannot cite a specific tool execution → RETRACT the finding.**

Example of a supported finding:
> "p.exe (PID 8260) was identified as malicious based on:
> - `windows.psscan` showing the process at path `c:\windows\temp\perfmon\p.exe`
> - `windows.malfind` showing a 481-page RWX region at 0x2be0000
> - `windows.filescan` confirming `P.EXE-1209D82B.pf` in Prefetch"

Example of an unsupported finding (RETRACT THIS):
> "The attacker likely exfiltrated data via DNS tunneling"
> (No tool output supports this claim)

### Step 2: METHODOLOGY CHECK

Verify you ran all required analysis steps:

| Step | Plugin | Did I run it? | Key insight extracted? |
|------|--------|--------------|----------------------|
| Process enumeration | `windows.psscan` | ☐ | ☐ |
| Process tree | `windows.pstree` | ☐ | ☐ |
| Command lines | `windows.cmdline` | ☐ | ☐ |
| Network connections | `windows.netscan` | ☐ | ☐ |
| Code injection | `windows.malfind` | ☐ | ☐ |
| File scan | `windows.filescan` | ☐ | ☐ |
| Credential context | `windows.getsids` | ☐ | ☐ |

**If any step was skipped → run it now and integrate the results.**

Don't just run the plugin — extract the forensically relevant insight.
Running `psscan` and listing 146 processes is not analysis.
Identifying that `p.exe` has 2 threads, a suspicious path, and was created
8 hours after boot — that's analysis.

### Step 3: CONSISTENCY CHECK

Review your findings for internal contradictions:

- If you claim a process is malicious, does its parent chain support that?
  (Legitimate parent → malicious child requires an explanation like injection or exploitation)
- If you claim lateral movement, is there network evidence to corroborate?
- If you claim persistence, did you actually find a persistence mechanism?
- Do your timestamps tell a coherent story? (Effect must follow cause)

**If findings contradict each other → resolve the contradiction.**
Either retract one finding or explain why both can be true.

### Step 4: FALSE POSITIVE REVIEW

Check these known false positive patterns in malfind output:

| Process | Signature | Reason |
|---------|-----------|--------|
| OUTLOOK.EXE | `64 74 72 52` (dtrR) at region start | Known Outlook memory allocation pattern |
| .NET processes | RWX regions in CLR/JIT areas | .NET CLR JIT-compiled code |
| AV updaters (McAfee, etc.) | Small RWX regions (1-2 pages) | Self-modifying code for signature updates |

**If you flagged any of these as malicious → correct your assessment.**
Mark them explicitly as "likely false positive" with the reason.

An agent that correctly identifies false positives is more valuable than
one that flags everything as malicious.

### Step 5: CLASSIFICATION

Rate each finding using these levels:

| Level | Criteria | Example |
|-------|----------|---------|
| **CONFIRMED** | Supported by 2+ tool outputs with consistent evidence | p.exe: psscan shows process, malfind shows RWX, filescan shows prefetch |
| **UNCONFIRMED** | Supported by 1 tool output or inferred from context | procdump.exe in Dashlane dir: only seen in filescan, could be legitimate |
| **RETRACTED** | Initially claimed but withdrawn after this review | "DNS tunneling" with no netscan evidence of DNS anomalies |

Be honest. UNCONFIRMED findings with clear reasoning are more valuable than
CONFIRMED claims with weak evidence.

---

## Post-Correction Output

After completing all steps, save your corrected findings:

```bash
cat > ./analysis/findings_post_correction.json << 'CORRECTED'
[paste your corrected findings as JSON array here]
CORRECTED
```

Then generate the diff:

```bash
diff ./analysis/findings_pre_correction.json ./analysis/findings_post_correction.json > ./analysis/correction_diff.txt
```

The diff shows what self-correction changed. This is a key artifact for the benchmark.

---

## What Good Self-Correction Looks Like

**Good:** "I initially flagged OUTLOOK.EXE (PID 8128) malfind hits as suspicious code injection.
On review, the RWX regions begin with the byte pattern `64 74 72 52` (dtrR), which is a
known Outlook memory allocation signature. RETRACTED — reclassified as false positive."

**Good:** "I did not run `windows.getsids` during initial analysis. Running it now on PID 5848
reveals the process runs as `spsql` with Domain Admin privileges. Adding this as a new
CONFIRMED finding."

**Bad:** Silently removing a finding without explanation.

**Bad:** Keeping a finding you can't support because retracting it "looks bad."

**Bad:** Skipping self-correction because "the analysis was thorough enough."
