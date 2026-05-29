"""
Tests for scorer/scorer.py error handling around the judge loop.

A single bad verdict (JudgeParseError) must NOT abort a multi-hour run.
JudgeApiError (5 retries exhausted) still propagates.

Run with:  python -m pytest tests/test_judge_error_handling.py -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from scorer.judge import JudgeApiError, JudgeParseError
from scorer.judge_cache import JudgeVerdict, PrecisionVerdict
from scorer import scorer as scorer_mod


def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def _minimal_gt():
    return {
        "case_id": "test",
        "severity_weights": {"critical": 4, "high": 2, "medium": 1, "low": 0.5},
        "findings": [
            {
                "id": "F001",
                "title": "Malicious process p.exe in user temp",
                "description": "p.exe staged in AppData\\Local\\Temp",
                "severity": "critical",
                "must_find": True,
                "evidence": {"process_name": "p.exe", "pid": 4216},
            },
            {
                "id": "F002",
                "title": "PowerShell C2 shell",
                "description": "powershell.exe with encoded command line",
                "severity": "high",
                "must_find": False,
                "evidence": {"process_name": "powershell.exe"},
            },
        ],
        "false_positive_traps": [],
        "negative_assertions": [],
    }


def _minimal_agent_findings():
    return [
        {
            "id": "A1",
            "title": "p.exe staged in AppData temp",
            "description": "Suspicious binary p.exe at C:\\Users\\...\\Temp",
            "status": "CONFIRMED",
            "severity": "critical",
            "evidence": {"process_name": "p.exe", "pid": 4216},
        },
        {
            "id": "A2",
            "title": "PowerShell with encoded command",
            "description": "powershell.exe -enc ... long base64 string",
            "status": "CONFIRMED",
            "severity": "high",
            "evidence": {"process_name": "powershell.exe"},
        },
        {
            "id": "A3",
            "title": "Outlook dtrR pattern — flagged then retracted",
            "description": "Initially flagged as injection; reviewed and retracted as legitimate Outlook telemetry.",
            "status": "RETRACTED",
            "severity": "low",
            "evidence": {"process_name": "outlook.exe"},
        },
    ]


class JudgeErrorHandlingTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.gt_path = _write_json(self.tmp / "gt.json", _minimal_gt())
        self.findings_path = _write_json(
            self.tmp / "findings.json",
            {"findings": _minimal_agent_findings()},
        )

        # Point the cache somewhere ephemeral so we don't poison scorer_cache/.
        from scorer.judge_cache import JudgeCache as _RealCache

        class _TmpCache(_RealCache):
            def __init__(_self):
                super().__init__(self.tmp / "cache.json")

        self._cache_orig = scorer_mod.JudgeCache
        scorer_mod.JudgeCache = _TmpCache

        # Avoid real Anthropic client construction (it requires an API key).
        self._client_patch = patch("anthropic.Anthropic")
        self._client_patch.start()

    def tearDown(self):
        scorer_mod.JudgeCache = self._cache_orig
        self._client_patch.stop()
        self._tmp.cleanup()

    def test_parse_error_on_one_pair_does_not_abort_run(self):
        """A single JudgeParseError mid-loop is logged and skipped."""

        # First judge_pair call raises; subsequent calls return a match verdict.
        # The first GT finding's match loop will exhaust top-3 candidates if all
        # raise; here only the first call raises, so a later candidate may match.
        call_count = {"n": 0}

        def flaky_judge_pair(gt, af, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise JudgeParseError("synthetic unparseable verdict")
            return JudgeVerdict(match=True, confidence=5, reasoning="ok")

        def stable_fallback(gt, af, **kw):
            return JudgeVerdict(match=False, confidence=5, reasoning="no")

        def stable_precision(af, **kw):
            return PrecisionVerdict(legitimate=True, confidence=5, reasoning="ok")

        with patch.object(scorer_mod, "judge_pair", side_effect=flaky_judge_pair), \
             patch.object(scorer_mod, "judge_fallback_pair", side_effect=stable_fallback), \
             patch.object(scorer_mod, "judge_precision", side_effect=stable_precision):
            results = scorer_mod.score(str(self.gt_path), str(self.findings_path))

        # Score completed (didn't raise) and produced a results dict.
        self.assertIn("weighted_f1", results)
        # At least one finding was matched despite the bad verdict on the first pair.
        self.assertGreaterEqual(len(results["findings_matched"]), 1)

    def test_parse_error_in_precision_pass_counts_as_uncertain(self):
        """A JudgeParseError during precision is logged and recorded as uncertain."""

        def no_match_judge(gt, af, **kw):
            return JudgeVerdict(match=False, confidence=5, reasoning="no")

        def failing_precision(af, **kw):
            raise JudgeParseError("synthetic precision parse error")

        with patch.object(scorer_mod, "judge_pair", side_effect=no_match_judge), \
             patch.object(scorer_mod, "judge_fallback_pair", side_effect=no_match_judge), \
             patch.object(scorer_mod, "judge_precision", side_effect=failing_precision):
            results = scorer_mod.score(str(self.gt_path), str(self.findings_path))

        # All agent findings landed in uncertain because precision parsing failed.
        self.assertEqual(results["count_fp"], 0)
        self.assertEqual(results["count_legit_unmatched"], 0)
        self.assertEqual(results["count_uncertain"], len(_minimal_agent_findings()))
        # Parse-error verdicts are recorded with reasoning indicating the error.
        for v in results["precision_verdicts"]:
            self.assertIn("parse_error", v["reasoning"])

    def test_api_error_still_aborts_run(self):
        """JudgeApiError (5 retries exhausted) still propagates."""

        def api_failure(gt, af, **kw):
            raise JudgeApiError("synthetic API outage")

        with patch.object(scorer_mod, "judge_pair", side_effect=api_failure):
            with self.assertRaises(JudgeApiError):
                scorer_mod.score(str(self.gt_path), str(self.findings_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
