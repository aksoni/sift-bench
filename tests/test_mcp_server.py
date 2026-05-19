import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_server.tools import hash_file

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
