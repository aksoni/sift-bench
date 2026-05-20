# Tool Executor v1 — Design Document

**Committed:** 2026-05-20 (before any implementation code)
**Maps to:** "Constraint Implementation" hackathon judging criterion
**Proposal language:** "Architectural guardrails: command allowlisting, evidence directory
write blocking. Not prompt-based."

---

## Purpose

The CLAUDE.md methodology constrains the agent via natural-language prohibitions.
These are prompt-based constraints: they work because the agent cooperates. The tool
executor is an architectural constraint: a Python subprocess wrapper that enforces
the same rules at the code level regardless of what the agent requests.

This is a v2 component. It is NOT retroactively applied to Runs 1–6; doing so would
change the experimental baseline. It is documented as a production-grade architectural
addition that a deployed DFIR system would require.

---

## What it is

A single Python module (`tool_executor.py`) exposing a `ToolExecutor` class. Callers
pass a command list (same signature as `subprocess.run`); the executor enforces:

1. **Command allowlisting** — only explicitly approved command stems can execute
2. **Evidence-directory write blocking** — output-path arguments that resolve inside
   blocked directories are rejected before any subprocess is spawned
3. **Structured execution logging** — every invocation (allowed or blocked) is appended
   as a JSON record to an audit log

`shell=False` is enforced unconditionally. Shell metacharacters in arguments are
literal characters, not interpreted by a shell — this prevents command injection via
argument manipulation.

---

## Command allowlist

Allowlisted by command stem (the basename of `args[0]`). A stem not in this set
raises `BlockedCommandError` before the subprocess is spawned.

```
Volatility 3:        vol
Sleuth Kit:          fls, icat, ils, blkls, mactime, tsk_recover
EWF tools:           ewfmount, ewfinfo, ewfverify
Plaso:               log2timeline.py, psort.py, pinfo.py
bulk_extractor:      bulk_extractor
Python runtime:      python3, python  (for MCP server and utility scripts)
dotnet runtime:      dotnet           (for EZ Tools)
Read-only utilities: sha256sum, md5sum, sha1sum, strings, file, stat,
                     grep, find, ls, cat, head, tail, sort, uniq, wc,
                     cut, awk, sed, xxd, hexdump, openssl
```

**What is NOT allowlisted:** rm, chmod, chown, dd, mkfs, mount (without ewf* prefix),
curl, wget, nc, ncat, ssh, scp, python -c (inline code), bash, sh, any shell.

Allowlist is defined as a module-level constant so it can be imported, audited, and
extended without touching executor logic.

---

## Evidence-directory write blocking

**Blocked directory prefixes** (after `os.path.realpath()` resolution):

```
/cases/
/mnt/
/media/
any path component named evidence/  (checked as a path segment, not substring)
```

**Why `realpath()`, not `abspath()`:** `abspath()` resolves `.` and `..` but does not
follow symlinks. An argument like `/tmp/evil` where `/tmp/evil` is a symlink to
`/cases/active/` would pass an `abspath()` check. `realpath()` resolves the full
symlink chain before comparison.

**What is inspected:** not just the command name — output-path arguments. The executor
inspects every argument immediately following a known output-flag:

```
-o  --output  -d  --outdir  --output-dir  --destination  --log-file  --logfile
```

If any such argument resolves inside a blocked directory (via `realpath()`), the call
raises `EvidenceDirWriteError` before spawning.

**Reading from blocked directories is allowed.** The check is on *output* arguments
only. Volatility, fls, icat etc. read from evidence directories by design — that is
the correct behavior.

**Limitation:** output arguments not preceded by a recognized output-flag are not
caught (e.g., a positional output argument). Documented as a known limitation; the
flag-based check covers the main cases for allowlisted DFIR tools. Full coverage
would require per-tool argument schemas (out of scope for v1).

---

## Structured execution log

Every call to `ToolExecutor.run()` appends one JSON record to the audit log file
(default: `./analysis/tool_executor_audit.jsonl`):

```json
{
  "timestamp_utc":  "2026-05-20T12:34:56.789Z",
  "command":        ["vol", "-f", "/cases/srl-2018/evidence/base-rd01.img", "windows.psscan"],
  "allowed":        true,
  "block_reason":   null,
  "blocked_value":  null,
  "returncode":     0,
  "duration_ms":    4217,
  "stdout_bytes":   18432,
  "stderr_bytes":   0
}
```

For blocked calls, `allowed` is `false`, `block_reason` is `"not_allowlisted"` or
`"evidence_dir_write"`, `blocked_value` is the offending command stem or path,
and `returncode` / `duration_ms` are `null`.

---

## Error types

```python
class BlockedCommandError(RuntimeError):
    """Raised when args[0] stem is not in the allowlist."""

class EvidenceDirWriteError(RuntimeError):
    """Raised when an output-flag argument resolves inside a blocked directory."""
```

Both are subclasses of `RuntimeError` so callers can catch them together or
individually.

---

## API

```python
executor = ToolExecutor(
    audit_log_path="./analysis/tool_executor_audit.jsonl",
    extra_allowed_commands=None,   # extend allowlist for testing
    extra_blocked_dirs=None,       # extend blocked dirs
)

result = executor.run(
    args=["vol", "-f", "/cases/.../evidence.img", "windows.psscan"],
    capture_output=True,
    timeout=300,
)
# Returns subprocess.CompletedProcess on success.
# Raises BlockedCommandError or EvidenceDirWriteError before spawning.
```

`ToolExecutor.run()` wraps `subprocess.run()` with `shell=False` unconditionally.
All kwargs except `shell` are passed through.

---

## Test plan (`tests/test_tool_executor.py`)

| # | Description | Expected |
|---|-------------|---------|
| 1 | Allowlisted command (`grep`) runs successfully | `returncode == 0`, audit log entry written |
| 2 | Non-allowlisted command (`rm`) raises | `BlockedCommandError` |
| 3 | Non-allowlisted command (`curl`) raises | `BlockedCommandError` |
| 4 | Output to evidence dir via `-o /cases/x` raises | `EvidenceDirWriteError` |
| 5 | Output to evidence dir via `--output /mnt/x` raises | `EvidenceDirWriteError` |
| 6 | Symlink to evidence dir via `-o /tmp/evil_link` raises | `EvidenceDirWriteError` (realpath resolves) |
| 7 | Reading from evidence dir (no output flag) is allowed | success |
| 8 | Audit log records blocked call with correct fields | block_reason set, allowed=false |
| 9 | Audit log records successful call with returncode | returncode == 0, duration_ms > 0 |
| 10 | `shell=False` verified — shell metacharacter in arg is literal | arg passed verbatim, no injection |

---

## Files to be created

- `tool_executor.py` — implementation (~120 lines)
- `tests/test_tool_executor.py` — 10 test cases
- No CLAUDE.md changes in this commit (v2 component; integration is a separate decision)

---

## Known limitation: `python3`/`python` are arbitrary execution

`python3` and `python` are in the allowlist because the MCP server and utility
scripts require them. This means the evidence-write guarantee is **best-effort for
those two stems, not absolute.** A call like:

```
python3 -c "open('/cases/srl-2018/evidence/x.txt', 'w').write('tampered')"
```

passes the allowlist check and the output-flag inspection (no `-o` flag present),
and writes directly into a blocked directory.

This is a sharper hole than the positional-argument limitation because `python3`
enables arbitrary code execution by design. In a production deployment this would
be addressed by restricting `python3` in the allowlist to a specific script path
(e.g., only `mcp_server/__main__.py`) rather than allowing the bare interpreter.
For SIFT-Bench v1 the scope is demonstration of the architectural pattern; the
limitation is documented here rather than papered over.

---

## Explicitly out of scope for v1

- Per-tool argument schemas for full output-path coverage
- Restricting `python3` to specific script paths (addresses the above limitation)
- Seccomp/namespaces/cgroups (OS-level sandboxing)
- Network egress blocking
- Retroactive application to Runs 1–6
- Integration with the live agent loop (v2 component only)
