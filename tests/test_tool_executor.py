"""
Tests for tool_executor.py — ToolExecutor v1.

Covers: allowlist enforcement, evidence-dir write blocking (direct + symlink),
audit log correctness, shell=False enforcement.

Run with:  python -m pytest tests/test_tool_executor.py -v
           python tests/test_tool_executor.py          (standalone)
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tool_executor import (
    BlockedCommandError,
    EvidenceDirWriteError,
    ToolExecutor,
)


class ToolExecutorTests(unittest.TestCase):

    def setUp(self):
        # Each test gets a fresh temp dir for the audit log and fake evidence dirs
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.audit_log = self.tmp / "audit.jsonl"

        # Fake evidence directory (stands in for /cases/)
        self.evidence_dir = self.tmp / "cases" / "srl-2018" / "evidence"
        self.evidence_dir.mkdir(parents=True)

        self.executor = ToolExecutor(
            audit_log_path=str(self.audit_log),
            extra_blocked_dirs=(str(self.tmp / "cases") + "/",),
        )

    def tearDown(self):
        self._tmpdir.cleanup()

    def _audit_records(self):
        if not self.audit_log.exists():
            return []
        return [json.loads(line) for line in self.audit_log.read_text().splitlines()]

    # ── 1. Allowlisted command runs ─────────────────────────────────────────

    def test_allowlisted_command_succeeds(self):
        result = self.executor.run(["grep", "--version"], capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_allowlisted_command_audit_entry(self):
        self.executor.run(["grep", "--version"], capture_output=True)
        records = self._audit_records()
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertTrue(r["allowed"])
        self.assertIsNone(r["block_reason"])
        self.assertEqual(r["returncode"], 0)
        self.assertGreater(r["duration_ms"], 0)
        self.assertIn("timestamp_utc", r)

    # ── 2 & 3. Non-allowlisted commands blocked ─────────────────────────────

    def test_rm_is_blocked(self):
        with self.assertRaises(BlockedCommandError) as ctx:
            self.executor.run(["rm", "-rf", "/tmp/something"])
        self.assertIn("rm", str(ctx.exception))

    def test_curl_is_blocked(self):
        with self.assertRaises(BlockedCommandError):
            self.executor.run(["curl", "http://example.com"])

    def test_bash_is_blocked(self):
        with self.assertRaises(BlockedCommandError):
            self.executor.run(["bash", "-c", "echo hi"])

    # ── 4 & 5. Evidence-dir write blocking via output flags ─────────────────

    def test_output_flag_direct_path_blocked(self):
        blocked_path = str(self.evidence_dir / "output.txt")
        with self.assertRaises(EvidenceDirWriteError) as ctx:
            self.executor.run(["grep", "pattern", "-o", blocked_path], capture_output=True)
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_output_long_flag_direct_path_blocked(self):
        blocked_path = str(self.tmp / "cases" / "output_dir")
        with self.assertRaises(EvidenceDirWriteError):
            self.executor.run(["find", ".", "--output", blocked_path], capture_output=True)

    # ── 6. Symlink to evidence dir is blocked (realpath resolution) ──────────

    def test_symlink_to_evidence_dir_blocked(self):
        symlink_path = self.tmp / "evil_link"
        symlink_path.symlink_to(self.evidence_dir)
        with self.assertRaises(EvidenceDirWriteError) as ctx:
            self.executor.run(
                ["grep", "pattern", "-o", str(symlink_path)],
                capture_output=True,
            )
        self.assertIn(str(symlink_path), str(ctx.exception))

    # ── 7. Reading from evidence dir is allowed ──────────────────────────────

    def test_reading_from_evidence_dir_allowed(self):
        # Create a readable file inside the evidence dir
        target = self.evidence_dir / "sample.txt"
        target.write_text("hello")
        # grep reading from that path — no output flag — should be allowed
        result = self.executor.run(
            ["grep", "hello", str(target)],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0)

    # ── 8. Blocked call audit log fields ────────────────────────────────────

    def test_blocked_call_audit_entry(self):
        with self.assertRaises(BlockedCommandError):
            self.executor.run(["rm", "/tmp/x"])
        records = self._audit_records()
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertFalse(r["allowed"])
        self.assertEqual(r["block_reason"], "not_allowlisted")
        self.assertEqual(r["blocked_value"], "rm")
        self.assertIsNone(r["returncode"])
        self.assertIsNone(r["duration_ms"])

    def test_evidence_write_block_audit_entry(self):
        blocked_path = str(self.evidence_dir / "out.txt")
        with self.assertRaises(EvidenceDirWriteError):
            self.executor.run(["grep", "x", "-o", blocked_path], capture_output=True)
        records = self._audit_records()
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertFalse(r["allowed"])
        self.assertEqual(r["block_reason"], "evidence_dir_write")
        self.assertEqual(r["blocked_value"], blocked_path)

    # ── 9. Successful call audit log has returncode and duration ─────────────

    def test_successful_audit_has_returncode_and_duration(self):
        self.executor.run(["grep", "--version"], capture_output=True)
        r = self._audit_records()[0]
        self.assertIsNotNone(r["returncode"])
        self.assertIsNotNone(r["duration_ms"])
        self.assertIsInstance(r["duration_ms"], int)

    # ── 10. shell=False — metacharacter in arg is literal, not injected ──────

    def test_shell_metacharacter_is_literal(self):
        # If shell=True were used, "; rm -rf /" would be executed as a shell command.
        # With shell=False it's a literal argument to grep, which returns non-zero
        # (no match) but does NOT execute the injected command.
        outfile = self.tmp / "result.txt"
        result = self.executor.run(
            ["grep", "; rm -rf /", "/dev/null"],
            capture_output=True,
        )
        # grep returns 1 when no match found — that's expected and safe
        self.assertIn(result.returncode, (0, 1))
        # The injected command did not run — /tmp still exists
        self.assertTrue(Path("/tmp").exists())

    # ── Bonus: evidence segment in path is blocked regardless of prefix ──────

    def test_evidence_segment_in_arbitrary_path_blocked(self):
        # /tmp/workdir/evidence/output.txt — no blocked-dir prefix,
        # but 'evidence' segment triggers blocking
        with self.assertRaises(EvidenceDirWriteError):
            self.executor.run(
                ["grep", "x", "-o", "/tmp/workdir/evidence/output.txt"],
                capture_output=True,
            )

    # ── Single-token output flag forms ──────────────────────────────────────

    def test_long_flag_equals_path_blocked(self):
        """`--output=PATH` form should be inspected, not skipped."""
        blocked_path = str(self.evidence_dir / "out.txt")
        with self.assertRaises(EvidenceDirWriteError):
            self.executor.run(
                ["find", ".", f"--output={blocked_path}"],
                capture_output=True,
            )

    def test_long_flag_equals_safe_path_allowed(self):
        """`--output=PATH` outside evidence dirs must still run."""
        safe_path = str(self.tmp / "ok.txt")
        result = self.executor.run(
            ["grep", "--version", f"--output={safe_path}"],
            capture_output=True,
        )
        # grep --version doesn't actually use --output= but it shouldn't error
        # out on our pre-check — exit code is grep's business, not ours.
        self.assertIn(result.returncode, (0, 1, 2))

    def test_short_flag_concatenated_path_blocked(self):
        """`-oPATH` form (short flag glued to value) should be inspected."""
        blocked_path = str(self.evidence_dir / "out.txt")
        with self.assertRaises(EvidenceDirWriteError):
            self.executor.run(
                ["grep", "x", f"-o{blocked_path}", "/dev/null"],
                capture_output=True,
            )

    def test_short_flag_concatenated_safe_path_allowed(self):
        """`-oPATH` outside evidence dirs must still run."""
        safe_path = str(self.tmp / "ok.txt")
        result = self.executor.run(
            ["grep", "x", f"-o{safe_path}", "/dev/null"],
            capture_output=True,
        )
        self.assertIn(result.returncode, (0, 1, 2))

    def test_equals_in_non_output_arg_does_not_falsepositive(self):
        """A non-output arg containing `=` should not be flagged."""
        # `--include=*.txt` is not an output flag; must not raise.
        result = self.executor.run(
            ["grep", "--include=*.txt", "x", "/dev/null"],
            capture_output=True,
        )
        self.assertIn(result.returncode, (0, 1, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
