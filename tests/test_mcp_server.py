import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_server.tools import hash_file, yara_scan

FIXTURE = Path(__file__).parent / "fixtures" / "test_file.txt"

# Hardcoded expected values — computed once from the committed fixture file,
# not derived dynamically (that would be tautological).
FIXTURE_SIZE = 53
FIXTURE_MD5 = "456fd60380722ca86a13304bd79094e7"
FIXTURE_SHA1 = "ca8e74c325ce659ce344352d56992a701a5c759d"
FIXTURE_SHA256 = "6231b4db034cc5e388ce61f4e7161d69d53802c908735bbbead1d11054eb1ed2"


class TestHashFile(unittest.TestCase):
    def test_known_fixture(self):
        result = hash_file(str(FIXTURE))
        self.assertNotIn("error", result, f"Unexpected error: {result.get('error')}")
        self.assertEqual(result["path"], str(FIXTURE))
        self.assertEqual(result["size_bytes"], FIXTURE_SIZE)
        self.assertEqual(result["md5"], FIXTURE_MD5)
        self.assertEqual(result["sha1"], FIXTURE_SHA1)
        self.assertEqual(result["sha256"], FIXTURE_SHA256)

    def test_missing_file(self):
        result = hash_file("/nonexistent/sift-bench-test/missing.bin")
        self.assertEqual(result["error"], "file_not_found")
        self.assertEqual(result["path"], "/nonexistent/sift-bench-test/missing.bin")
        self.assertIn("detail", result)

    def test_not_a_regular_file_directory(self):
        result = hash_file(os.path.dirname(__file__))
        self.assertEqual(result["error"], "not_a_regular_file")
        self.assertIn("detail", result)


YARA_RULES_DIR = Path(__file__).parent / "yara_rules"
TEST_MARKER_RULE = YARA_RULES_DIR / "test_marker.yar"

# Hardcoded expected values — computed once from the committed fixture and rule files.
FIXTURE_SHA256 = "6231b4db034cc5e388ce61f4e7161d69d53802c908735bbbead1d11054eb1ed2"
TEST_MARKER_RULE_SHA256 = "c770b8ca4ad9859d6d12b56da417dd8a89614df404b6348aa60a41f9dac2303b"
FIND_EVIL_MARKER_HEX = "46494e445f4556494c5f4d41524b4552"  # "FIND_EVIL_MARKER" as lowercase hex


class TestYaraScan(unittest.TestCase):
    def test_known_fixture_match(self):
        result = yara_scan(str(FIXTURE), str(TEST_MARKER_RULE))
        self.assertNotIn("error", result, f"Unexpected error: {result.get('error')}")
        self.assertEqual(result["target_path"], str(FIXTURE))
        self.assertEqual(result["target_sha256"], FIXTURE_SHA256)
        self.assertEqual(result["rules_path"], str(TEST_MARKER_RULE))
        self.assertEqual(result["rules_sha256"], TEST_MARKER_RULE_SHA256)
        self.assertIn("scan_duration_ms", result)
        self.assertIsInstance(result["scan_duration_ms"], int)
        self.assertEqual(len(result["matches"]), 1)
        m = result["matches"][0]
        self.assertEqual(m["rule"], "TestMarker")
        self.assertEqual(m["namespace"], "default")
        self.assertEqual(m["tags"], [])
        self.assertIn("description", m["meta"])
        self.assertEqual(len(m["strings"]), 1)
        s = m["strings"][0]
        self.assertEqual(s["identifier"], "$marker")
        self.assertEqual(s["offset"], 0)
        self.assertEqual(s["data"], FIND_EVIL_MARKER_HEX)

    def test_no_match(self):
        rule_src = 'rule NoMatch { strings: $x = "SIFT_BENCH_NO_MATCH_XYZ_999" condition: $x }'
        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as rf:
            rf.write(rule_src)
            rf_path = rf.name
        try:
            result = yara_scan(str(FIXTURE), rf_path)
            self.assertNotIn("error", result)
            self.assertEqual(result["matches"], [])
        finally:
            os.unlink(rf_path)

    def test_missing_target(self):
        result = yara_scan("/nonexistent/sift-bench-test/missing.bin", str(TEST_MARKER_RULE))
        self.assertEqual(result["error"], "target_not_found")
        self.assertIn("detail", result)

    def test_missing_rules(self):
        result = yara_scan(str(FIXTURE), "/nonexistent/sift-bench-test/missing.yar")
        self.assertEqual(result["error"], "rules_not_found")
        self.assertIn("detail", result)

    def test_rules_compile_error(self):
        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as rf:
            rf.write("rule Bad { this is not valid yara syntax }")
            rf_path = rf.name
        try:
            result = yara_scan(str(FIXTURE), rf_path)
            self.assertEqual(result["error"], "rules_compile_error")
            self.assertIn("detail", result)
        finally:
            os.unlink(rf_path)

    def test_target_not_a_regular_file(self):
        result = yara_scan(os.path.dirname(__file__), str(TEST_MARKER_RULE))
        self.assertEqual(result["error"], "target_not_a_regular_file")
        self.assertIn("detail", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
