"""
Tests for srl-2018-novel.yar — SIFT_Procdump_Sysinternals_Marker
and SIFT_PS_SysWOW64_Stealth_Memory.

Fixtures are generated in-process as byte strings so no binary files need
to be committed to the repo. Uses the yara-python module (pip install yara-python).

Run with:  python -m pytest tests/test_yara_novel.py -v
           python tests/test_yara_novel.py          (standalone)
"""

import os
import sys
import unittest

try:
    import yara
except ImportError:
    print("yara-python not installed — run: pip install yara-python")
    sys.exit(1)

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "yara_rules", "srl-2018-novel.yar")

_compiled = None

def _rules():
    global _compiled
    if _compiled is None:
        _compiled = yara.compile(RULES_PATH)
    return _compiled


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def _run_yara(rule_name: str, data: bytes) -> bool:
    """Return True if rule_name fires against data."""
    matches = _rules().match(data=data)
    return any(m.rule == rule_name for m in matches)


class TestProcdumpSysinternalsMarker(unittest.TestCase):
    RULE = "SIFT_Procdump_Sysinternals_Marker"

    def test_positive_both_strings_present(self):
        data = _utf16le("ProcDump") + b"\x00\x00" + _utf16le("Sysinternals")
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: both ProcDump and Sysinternals (wide) present")

    def test_positive_procdump_and_russinovich(self):
        data = _utf16le("ProcDump") + b"\x00\x00" + _utf16le("Mark Russinovich")
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: ProcDump + Mark Russinovich (wide) present")

    def test_positive_all_three_strings(self):
        data = (
            _utf16le("ProcDump") + b"\x00\x00" +
            _utf16le("Sysinternals - www.sysinternals.com") + b"\x00\x00" +
            _utf16le("Mark Russinovich")
        )
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: all three strings present")

    def test_negative_only_one_string(self):
        data = _utf16le("ProcDump")
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: only one string — condition requires 2 of 3")

    def test_negative_unrelated_content(self):
        data = b"This file has nothing to do with Sysinternals or ProcDump in any encoding"
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: no relevant strings")

    def test_negative_ascii_only_not_wide(self):
        # ASCII (not wide) — rule requires wide; should not match
        data = b"ProcDump\x00Sysinternals\x00"
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: strings present as ASCII, not UTF-16LE wide")


class TestPSSysWOW64StealthMemory(unittest.TestCase):
    RULE = "SIFT_PS_SysWOW64_Stealth_Memory"

    def _build(self, path: bool, flags: list[str]) -> bytes:
        parts = []
        if path:
            parts.append(_utf16le("SysWOW64\\WindowsPowerShell"))
        for flag in flags:
            parts.append(_utf16le(flag))
        return b"\x00\x00".join(parts)

    def test_positive_path_and_three_flags(self):
        data = self._build(True, ["-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass"])
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: SysWOW64 path + 3 flags (wide)")

    def test_positive_path_and_four_flags(self):
        data = self._build(True, ["-NoProfile", "-NoExit", "-WindowStyle Hidden", "-ExecutionPolicy Bypass"])
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: SysWOW64 path + 4 flags (wide)")

    def test_positive_boundary_exactly_three_flags(self):
        data = self._build(True, ["-NonInteractive", "-NoLogo", "-EncodedCommand"])
        self.assertTrue(_run_yara(self.RULE, data),
            "Should match: boundary case — exactly 3 flags (threshold met)")

    def test_negative_only_two_flags(self):
        data = self._build(True, ["-NoProfile", "-WindowStyle Hidden"])
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: SysWOW64 path + only 2 flags (below threshold)")

    def test_negative_three_flags_no_path(self):
        data = self._build(False, ["-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass"])
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: 3 flags present but no SysWOW64 path indicator")

    def test_negative_ascii_flags_not_wide(self):
        # ASCII encoded flags — rule requires wide; memory images have UTF-16LE
        data = (
            b"SysWOW64\\WindowsPowerShell\x00"
            b"-NoProfile\x00-WindowStyle Hidden\x00-ExecutionPolicy Bypass\x00"
        )
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: strings present as ASCII, not UTF-16LE wide")

    def test_negative_unrelated_content(self):
        data = b"nothing relevant here at all"
        self.assertFalse(_run_yara(self.RULE, data),
            "Should NOT match: no relevant strings")


if __name__ == "__main__":
    unittest.main(verbosity=2)
