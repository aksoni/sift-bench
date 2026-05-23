"""
Tests for scorer/judge_cache.py — the `kind` tag added in task item 8.

Verifies:
  - put() / put_precision() write a `kind` field on every new entry
  - get() / get_precision() refuse to dereference a mismatched-kind entry
  - Legacy un-tagged entries (no `kind` field) are still readable via
    field-inspection inference, preserving reviewer reproducibility on
    the committed scorer_cache/judge_verdicts.json
  - The fallback `kind` is set when `_meta.via_fallback` is true

Run with:  python -m pytest tests/test_judge_cache.py -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scorer.judge_cache import (
    CacheKindMismatch,
    JudgeCache,
    JudgeVerdict,
    PrecisionVerdict,
)


class JudgeCacheKindTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_path = Path(self._tmp.name) / "cache.json"

    def tearDown(self):
        self._tmp.cleanup()

    # ── put() / put_precision() write `kind` ───────────────────────────────

    def test_put_writes_match_kind(self):
        cache = JudgeCache(self.cache_path)
        cache.put("k1", JudgeVerdict(match=True, confidence=5, reasoning="ok"))
        cache.save()
        entry = json.loads(self.cache_path.read_text())["k1"]
        self.assertEqual(entry["kind"], "match")

    def test_put_with_via_fallback_meta_writes_fallback_kind(self):
        cache = JudgeCache(self.cache_path)
        cache.put(
            "k1",
            JudgeVerdict(match=True, confidence=5, reasoning="ok"),
            meta={"via_fallback": True, "gt_id": "F001", "agent_id": "A1"},
        )
        cache.save()
        entry = json.loads(self.cache_path.read_text())["k1"]
        self.assertEqual(entry["kind"], "fallback")

    def test_put_precision_writes_precision_kind(self):
        cache = JudgeCache(self.cache_path)
        cache.put_precision(
            "k1", PrecisionVerdict(legitimate=False, confidence=4, reasoning="no")
        )
        cache.save()
        entry = json.loads(self.cache_path.read_text())["k1"]
        self.assertEqual(entry["kind"], "precision")

    # ── kind mismatches refused ────────────────────────────────────────────

    def test_get_on_precision_entry_raises(self):
        cache = JudgeCache(self.cache_path)
        cache.put_precision(
            "k1", PrecisionVerdict(legitimate=True, confidence=5, reasoning="ok")
        )
        with self.assertRaises(CacheKindMismatch):
            cache.get("k1")

    def test_get_precision_on_match_entry_raises(self):
        cache = JudgeCache(self.cache_path)
        cache.put("k1", JudgeVerdict(match=True, confidence=5, reasoning="ok"))
        with self.assertRaises(CacheKindMismatch):
            cache.get_precision("k1")

    # ── round-trip ─────────────────────────────────────────────────────────

    def test_match_roundtrip(self):
        cache = JudgeCache(self.cache_path)
        v = JudgeVerdict(match=True, confidence=5, reasoning="matches")
        cache.put("k1", v)
        cache.save()
        cache2 = JudgeCache(self.cache_path)
        out = cache2.get("k1")
        self.assertEqual(out.match, True)
        self.assertEqual(out.confidence, 5)
        self.assertEqual(out.reasoning, "matches")

    def test_precision_roundtrip(self):
        cache = JudgeCache(self.cache_path)
        v = PrecisionVerdict(legitimate=False, confidence=4, reasoning="hallucinated")
        cache.put_precision("k1", v)
        cache.save()
        cache2 = JudgeCache(self.cache_path)
        out = cache2.get_precision("k1")
        self.assertEqual(out.legitimate, False)
        self.assertEqual(out.confidence, 4)
        self.assertEqual(out.reasoning, "hallucinated")

    # ── legacy un-tagged entries still readable ────────────────────────────

    def test_legacy_match_entry_without_kind_still_readable(self):
        """Reviewers cloning the repo before backfill must still get cache hits."""
        legacy = {
            "k1": {
                "match": True,
                "confidence": 5,
                "reasoning": "ok",
                "_meta": {"agent_id": "A1", "gt_id": "F001"},
            }
        }
        self.cache_path.write_text(json.dumps(legacy))
        cache = JudgeCache(self.cache_path)
        out = cache.get("k1")
        self.assertEqual(out.match, True)
        self.assertEqual(out.confidence, 5)

    def test_legacy_precision_entry_without_kind_still_readable(self):
        legacy = {
            "k1": {
                "legitimate": True,
                "confidence": 5,
                "reasoning": "ok",
            }
        }
        self.cache_path.write_text(json.dumps(legacy))
        cache = JudgeCache(self.cache_path)
        out = cache.get_precision("k1")
        self.assertEqual(out.legitimate, True)

    # ── committed cache is well-formed ─────────────────────────────────────

    def test_committed_cache_all_entries_have_kind(self):
        """scorer_cache/judge_verdicts.json must be backfilled for item 8."""
        committed = Path(__file__).parent.parent / "scorer_cache" / "judge_verdicts.json"
        if not committed.exists():
            self.skipTest("committed cache file absent")
        data = json.loads(committed.read_text())
        missing = [k for k, v in data.items() if "kind" not in v]
        self.assertEqual(
            missing, [],
            f"{len(missing)} cache entries are missing the `kind` tag",
        )
        # Every kind must be one of the three known values.
        known = {"match", "fallback", "precision"}
        bad = [k for k, v in data.items() if v["kind"] not in known]
        self.assertEqual(bad, [], f"unknown kinds present: {bad[:5]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
