"""
Tests for scorer/checklist.py and scorer/self_correction.py.

Uses synthetic fixtures for unit tests; also exercises the scorers against
real run data to catch regressions against known ground truth.

Run with:  python tests/test_scoring_additions.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scorer.checklist import score_checklist
from scorer.self_correction import score_self_correction

REPO = Path(__file__).parent.parent
GT_PATH = REPO / "ground_truth" / "base-rd01-v1.1.json"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def _make_log(entries, schema="run6"):
    """Build a minimal execution_log.json in the specified schema variant."""
    if schema == "run6":
        return {
            "case_id": "test",
            "execution_log": [
                {"seq": i+1, "command": cmd, "return_code": rc,
                 "timestamp_utc": "2026-01-01T00:00:00Z", "notes": ""}
                for i, (cmd, rc) in enumerate(entries)
            ],
        }
    elif schema == "run5":
        return {
            "case_id": "test",
            "tool_invocations": [
                {"step": i+1, "command": cmd, "status": "success" if rc == 0 else "error",
                 "output_file": "x.txt"}
                for i, (cmd, rc) in enumerate(entries)
            ],
        }
    elif schema == "run3":
        return {
            "case_id": "test",
            "tool_invocations": [
                {"command": cmd, "return_code": rc, "timestamp_utc": "2026-01-01T00:00:00Z"}
                for cmd, rc in entries
            ],
        }


ALL_9_PLUGINS = [
    ("vol -f img windows.psscan", 0),
    ("vol -f img windows.pstree", 0),
    ("vol -f img windows.cmdline", 0),
    ("vol -f img windows.netscan", 0),
    ("vol -f img windows.malfind", 0),
    ("vol -f img windows.filescan", 0),
    ("vol -f img windows.getsids --pid 1", 0),
    ("vol -f img windows.dlllist --pid 1", 0),
    ("vol -f img windows.svcscan", 0),
]


# ── Checklist tests ───────────────────────────────────────────────────────────

class TestChecklist(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _score(self, entries, schema="run6"):
        p = _write_json(self.tmp / "execution_log.json", _make_log(entries, schema))
        return score_checklist(p)

    def test_all_9_steps_pass(self):
        result = self._score(ALL_9_PLUGINS)
        self.assertEqual(result["passed"], 9)
        self.assertEqual(result["coverage"], 1.0)
        self.assertTrue(all(s["status"] == "pass" for s in result["steps"]))

    def test_missing_log_returns_zeros(self):
        result = score_checklist(self.tmp / "nonexistent.json")
        self.assertEqual(result["passed"], 0)
        self.assertIsNotNone(result["note"])

    def test_errored_step_does_not_count(self):
        entries = list(ALL_9_PLUGINS)
        # psscan fails (return_code=1)
        entries[0] = ("vol -f img windows.psscan", 1)
        result = self._score(entries)
        self.assertEqual(result["passed"], 8)
        psscan = next(s for s in result["steps"] if s["name"] == "psscan")
        self.assertEqual(psscan["status"], "fail")

    def test_persistence_satisfied_by_svcscan(self):
        entries = list(ALL_9_PLUGINS[:-1]) + [("vol -f img windows.svcscan", 0)]
        result = self._score(entries)
        persistence = next(s for s in result["steps"] if s["name"] == "persistence")
        self.assertEqual(persistence["status"], "pass")

    def test_persistence_satisfied_by_registry_printkey(self):
        entries = list(ALL_9_PLUGINS[:-1]) + [
            ("vol -f img windows.registry.printkey --key SOFTWARE\\Run", 0)
        ]
        result = self._score(entries)
        persistence = next(s for s in result["steps"] if s["name"] == "persistence")
        self.assertEqual(persistence["status"], "pass")

    def test_run5_status_schema(self):
        result = self._score(ALL_9_PLUGINS, schema="run5")
        self.assertEqual(result["passed"], 9)

    def test_run3_tool_invocations_schema(self):
        result = self._score(ALL_9_PLUGINS, schema="run3")
        self.assertEqual(result["passed"], 9)

    def test_missing_dlllist_shows_as_missing(self):
        entries = [e for e in ALL_9_PLUGINS if "dlllist" not in e[0]]
        result = self._score(entries)
        dlllist = next(s for s in result["steps"] if s["name"] == "dlllist")
        self.assertEqual(dlllist["status"], "missing")
        self.assertEqual(result["passed"], 8)

    # ── Real-run regression tests ─────────────────────────────────────────────

    def test_run1_real_data_8_of_9(self):
        log = REPO / "cases/srl-2018/run1_analysis/execution_log.json"
        if not log.exists():
            self.skipTest("run1 log not available")
        result = score_checklist(log)
        self.assertEqual(result["passed"], 8, "run1 should be 8/9 (dlllist not yet added)")

    def test_run6_real_data_9_of_9(self):
        log = REPO / "cases/srl-2018/run6_analysis/execution_log.json"
        if not log.exists():
            self.skipTest("run6 log not available")
        result = score_checklist(log)
        self.assertEqual(result["passed"], 9, "run6 should be 9/9")


# ── Self-correction tests ─────────────────────────────────────────────────────

class TestSelfCorrection(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _pre(self, findings):
        return _write_json(self.tmp / "pre.json", {"findings": findings, "phase": "pre_correction"})

    def _post(self, findings):
        return _write_json(self.tmp / "post.json", {"findings": findings, "phase": "post_correction"})

    def test_fp_trap_retracted_in_post(self):
        pre  = self._pre([{"id": "F01", "title": "OUTLOOK.EXE dtrR", "status": "CONFIRMED",
                            "description": "outlook dtrr injection suspicious", "category": "malware", "evidence": {}}])
        post = self._post([{"id": "F01", "title": "OUTLOOK.EXE dtrR", "status": "RETRACTED",
                            "description": "outlook dtrr injection suspicious", "category": "false_positive", "evidence": {}}])
        result = score_self_correction(pre, post)
        self.assertEqual(result["fp_traps_retracted_count"], 1)
        self.assertEqual(result["fp_traps_retracted"][0]["trap_id"], "FP001")

    def test_retraction_counted_correctly(self):
        pre  = self._pre([
            {"id": "F01", "status": "CONFIRMED", "title": "real", "description": "real finding", "category": "malware", "evidence": {}},
            {"id": "F02", "status": "CONFIRMED", "title": "outlook dtrR false", "description": "outlook dtrr", "category": "malware", "evidence": {}},
        ])
        post = self._post([
            {"id": "F01", "status": "CONFIRMED", "title": "real", "description": "real finding", "category": "malware", "evidence": {}},
            {"id": "F02", "status": "RETRACTED", "title": "outlook dtrR false", "description": "outlook dtrr", "category": "false_positive", "evidence": {}},
        ])
        result = score_self_correction(pre, post)
        self.assertEqual(result["retracted_count"], 1)
        self.assertIn("F02", result["findings_retracted"])

    def test_added_finding_detected(self):
        pre  = self._pre([{"id": "F01", "status": "CONFIRMED", "title": "existing", "description": "x", "category": "malware", "evidence": {}}])
        post = self._post([
            {"id": "F01", "status": "CONFIRMED", "title": "existing", "description": "x", "category": "malware", "evidence": {}},
            {"id": "F02", "status": "CONFIRMED", "title": "new finding", "description": "new", "category": "lateral_movement", "evidence": {}},
        ])
        result = score_self_correction(pre, post)
        self.assertEqual(result["added_count"], 1)
        self.assertIn("F02", result["findings_added"])

    def test_no_changes_all_zeros(self):
        findings = [{"id": "F01", "status": "CONFIRMED", "title": "t", "description": "d", "category": "malware", "evidence": {}}]
        pre  = self._pre(findings)
        post = self._post(findings)
        result = score_self_correction(pre, post)
        self.assertEqual(result["retracted_count"], 0)
        self.assertEqual(result["added_count"], 0)
        self.assertEqual(result["fp_traps_retracted_count"], 0)

    def test_missing_file_returns_error(self):
        result = score_self_correction(self.tmp / "ghost_pre.json", self.tmp / "ghost_post.json")
        self.assertIn("error", result)

    def test_mcafee_trap_detected(self):
        pre  = self._pre([{"id": "FP02", "title": "UpdaterUI suspicious", "status": "CONFIRMED",
                            "description": "mcafee updaterui process", "category": "malware", "evidence": {}}])
        post = self._post([{"id": "FP02", "title": "UpdaterUI suspicious", "status": "RETRACTED",
                            "description": "mcafee updaterui process", "category": "false_positive", "evidence": {}}])
        result = score_self_correction(pre, post)
        traps = [t["trap_id"] for t in result["fp_traps_retracted"]]
        self.assertIn("FP002", traps)

    def test_clr_heap_trap_detected(self):
        post_f = {"id": "F99", "status": "RETRACTED", "title": "CLR heap",
                   "description": "powershell clr heap 0xffeeffee false positive",
                   "category": "false_positive", "evidence": {}}
        pre  = self._pre([{**post_f, "status": "CONFIRMED"}])
        post = self._post([post_f])
        result = score_self_correction(pre, post)
        traps = [t["trap_id"] for t in result["fp_traps_retracted"]]
        self.assertIn("FP003", traps)

    # ── Real-run regression tests ─────────────────────────────────────────────

    def test_run2_real_data_two_fp_traps(self):
        base = REPO / "cases/srl-2018/run2_analysis"
        if not (base / "findings_pre_correction.json").exists():
            self.skipTest("run2 data not available")
        result = score_self_correction(
            base / "findings_pre_correction.json",
            base / "findings_post_correction.json",
            GT_PATH,
        )
        self.assertEqual(result["fp_traps_retracted_count"], 2,
                         "run2 caught 2/3 FP traps (McAfee not caught)")

    def test_run3_real_data_three_fp_traps(self):
        base = REPO / "cases/srl-2018/run3_analysis"
        if not (base / "findings_pre_correction.json").exists():
            self.skipTest("run3 data not available")
        result = score_self_correction(
            base / "findings_pre_correction.json",
            base / "findings_post_correction.json",
            GT_PATH,
        )
        self.assertEqual(result["fp_traps_retracted_count"], 3,
                         "run3 caught all 3 FP traps")

    def test_run6_real_data_three_fp_traps(self):
        base = REPO / "cases/srl-2018/run6_analysis"
        if not (base / "findings_pre_correction.json").exists():
            self.skipTest("run6 data not available")
        result = score_self_correction(
            base / "findings_pre_correction.json",
            base / "findings_post_correction.json",
            GT_PATH,
        )
        self.assertEqual(result["fp_traps_retracted_count"], 3,
                         "run6 caught all 3 FP traps")


if __name__ == "__main__":
    unittest.main(verbosity=2)
