"""
SIFT-Bench Tool Executor v1

Subprocess wrapper enforcing:
  - Command allowlisting (stem-based)
  - Evidence-directory write blocking (realpath-based, output-flag inspection)
  - Structured JSON audit logging

See design/tool-executor-v1.md for rationale, threat model, and known limitations.
This is a v2 architectural component; it is not applied retroactively to Runs 1-6.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class BlockedCommandError(RuntimeError):
    """Command stem is not in the allowlist."""

class EvidenceDirWriteError(RuntimeError):
    """An output-flag argument resolves inside a blocked evidence directory."""


# ---------------------------------------------------------------------------
# Allowlist — command stems that may be executed
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS: frozenset[str] = frozenset({
    # Volatility 3
    "vol",
    # Sleuth Kit
    "fls", "icat", "ils", "blkls", "mactime", "tsk_recover",
    # EWF tools
    "ewfmount", "ewfinfo", "ewfverify",
    # Plaso
    "log2timeline.py", "psort.py", "pinfo.py",
    # bulk_extractor / photorec
    "bulk_extractor",
    # Python runtime (MCP server, utility scripts)
    "python3", "python",
    # dotnet runtime (EZ Tools)
    "dotnet",
    # Read-only forensic / system utilities
    "sha256sum", "md5sum", "sha1sum",
    "strings", "file", "stat",
    "grep", "find", "ls", "cat", "head", "tail",
    "sort", "uniq", "wc", "cut", "awk", "sed",
    "xxd", "hexdump", "openssl",
})

# Flags that introduce an output path as the next argument
OUTPUT_FLAGS: frozenset[str] = frozenset({
    "-o", "--output",
    "-d", "--outdir", "--output-dir",
    "--destination",
    "--log-file", "--logfile",
})

# Blocked directory prefixes — realpath-resolved before comparison
DEFAULT_BLOCKED_DIRS: tuple[str, ...] = (
    "/cases/",
    "/mnt/",
    "/media/",
)

# Path segment name that always triggers blocking (e.g., any .../evidence/... path)
BLOCKED_SEGMENT = "evidence"


# ---------------------------------------------------------------------------
# ToolExecutor
# ---------------------------------------------------------------------------

class ToolExecutor:
    def __init__(
        self,
        audit_log_path: str | os.PathLike = "./analysis/tool_executor_audit.jsonl",
        extra_allowed_commands: set[str] | None = None,
        extra_blocked_dirs: tuple[str, ...] | None = None,
    ) -> None:
        self._audit_log = Path(audit_log_path)
        self._allowed = ALLOWED_COMMANDS | (extra_allowed_commands or set())
        self._blocked_dirs = DEFAULT_BLOCKED_DIRS + (extra_blocked_dirs or ())

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self, args: list[str], **kwargs) -> subprocess.CompletedProcess:
        """
        Execute args as a subprocess, enforcing allowlist and write-block rules.

        kwargs are passed to subprocess.run(); shell=False is enforced unconditionally.

        Raises:
            BlockedCommandError     — command stem not in allowlist
            EvidenceDirWriteError   — output-flag argument inside a blocked directory
        """
        kwargs.pop("shell", None)  # enforce shell=False regardless of caller

        stem = self._stem(args[0])
        self._check_allowlist(stem, args)
        self._check_output_args(args)

        start = time.monotonic()
        result = subprocess.run(args, shell=False, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        self._log(
            command=args,
            allowed=True,
            block_reason=None,
            blocked_value=None,
            returncode=result.returncode,
            duration_ms=elapsed_ms,
            stdout_bytes=len(result.stdout) if isinstance(result.stdout, (bytes, str)) else 0,
            stderr_bytes=len(result.stderr) if isinstance(result.stderr, (bytes, str)) else 0,
        )
        return result

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _stem(self, cmd: str) -> str:
        return os.path.basename(cmd)

    def _check_allowlist(self, stem: str, args: list[str]) -> None:
        if stem not in self._allowed:
            self._log(
                command=args,
                allowed=False,
                block_reason="not_allowlisted",
                blocked_value=stem,
                returncode=None, duration_ms=None, stdout_bytes=None, stderr_bytes=None,
            )
            raise BlockedCommandError(
                f"Command '{stem}' is not in the allowlist. "
                f"See tool_executor.ALLOWED_COMMANDS."
            )

    def _check_output_args(self, args: list[str]) -> None:
        """Inspect arguments following output flags for evidence-directory paths."""
        for i, arg in enumerate(args):
            if arg in OUTPUT_FLAGS and i + 1 < len(args):
                candidate = args[i + 1]
                resolved = os.path.realpath(candidate)
                if self._is_blocked(resolved):
                    self._log(
                        command=args,
                        allowed=False,
                        block_reason="evidence_dir_write",
                        blocked_value=candidate,
                        returncode=None, duration_ms=None, stdout_bytes=None, stderr_bytes=None,
                    )
                    raise EvidenceDirWriteError(
                        f"Output path '{candidate}' (resolved: '{resolved}') is inside "
                        f"a protected evidence directory. Write blocked."
                    )

    def _is_blocked(self, resolved_path: str) -> bool:
        # Blocked by prefix
        for prefix in self._blocked_dirs:
            real_prefix = os.path.realpath(prefix.rstrip("/")) + "/"
            if resolved_path.startswith(real_prefix) or resolved_path == real_prefix.rstrip("/"):
                return True
        # Blocked by path segment name (any .../evidence/... component)
        parts = Path(resolved_path).parts
        if BLOCKED_SEGMENT in parts:
            return True
        return False

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _log(self, **fields) -> None:
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
