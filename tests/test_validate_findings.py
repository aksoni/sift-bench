"""
Tests for scorer/validate_findings.py — dual-schema findings validator
(task item 2).

Coverage:
  - Permissive: accepts both top-level shapes (flat array, wrapper object)
  - Permissive: accepts every existing run's findings file (1-6)
  - Permissive: rejects findings missing id / title / description
  - Strict: enforces full CLAUDE.md schema (severity, status, confidence,
    category, evidence-as-object, tool_attribution)
  - Strict: enforces retraction_reason when status=RETRACTED
  - Strict: rejects Run 1's old schema (intended)
  - JSON parse errors surface as FindingsSchemaError

Run with:  python -m pytest tests/test_validate_findings.py -v
"""

import glob
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scorer.validate_findings import (
    FindingsSchemaError,
    validate_findings,
    validate_findings_file,
)


REPO = Path(__file__).parent.parent


def _well_formed_strict_finding(**overrides):
    """Return a finding object that passes strict validation; allow per-test overrides."""
    base = {
        "id": "F01",
        "title": "p.exe in user temp",
        "description": "Suspicious binary staged in AppData",
        "severity": "critical",
        "status": "CONFIRMED",
        "confidence": "high",
        "category": "malware",
        "evidence": {"process_name": "p.exe", "pid": 4216},
        "tool_attribution": ["vol -f mem.img windows.psscan"],
    }
    base.update(overrides)
    return base


def _well_formed_strict_doc(findings=None):
    return {
        "case_id": "test",
        "analyst": "test",
        "evidence_image": "mem.img",
        "analysis_timestamp_utc": "2026-05-23T00:00:00Z",
        "phase": "post_correction",
        "findings": findings if findings is not None else [_well_formed_strict_finding()],
        "summary": {
            "total_findings": 1,
            "confirmed_count": 1,
            "unconfirmed_count": 0,
            "retracted_count": 0,
        },
    }


class PermissiveTests(unittest.TestCase):

    def test_flat_array_accepted(self):
        data = [
            {"id": "F1", "title": "x", "description": "y"},
            {"id": "F2", "title": "a", "description": "b"},
        ]
        validate_findings(data, strict=False)  # must not raise

    def test_wrapper_object_accepted(self):
        data = {"findings": [{"id": "F1", "title": "x", "description": "y"}]}
        validate_findings(data, strict=False)

    def test_missing_required_field_rejected(self):
        # description is required by the permissive schema
        data = [{"id": "F1", "title": "x"}]
        with self.assertRaises(FindingsSchemaError) as ctx:
            validate_findings(data, strict=False)
        self.assertIn("description", str(ctx.exception))

    def test_empty_id_rejected(self):
        data = [{"id": "", "title": "x", "description": "y"}]
        with self.assertRaises(FindingsSchemaError):
            validate_findings(data, strict=False)

    def test_neither_shape_rejected(self):
        # A bare string is neither an array nor a wrapper object
        with self.assertRaises(FindingsSchemaError):
            validate_findings("not a findings doc", strict=False)

    def test_all_existing_runs_pass_permissive(self):
        """Backward-compat guard: every committed run must validate."""
        files = sorted(glob.glob(str(REPO / "cases" / "srl-2018" / "run*" / "findings*.json")))
        self.assertGreater(len(files), 0, "no existing run findings files found")
        for f in files:
            with self.subTest(file=f):
                validate_findings_file(f, strict=False)


class StrictTests(unittest.TestCase):

    def test_well_formed_doc_accepted(self):
        validate_findings(_well_formed_strict_doc(), strict=True)

    def test_missing_severity_rejected(self):
        f = _well_formed_strict_finding()
        del f["severity"]
        with self.assertRaises(FindingsSchemaError) as ctx:
            validate_findings(_well_formed_strict_doc([f]), strict=True)
        self.assertIn("severity", str(ctx.exception))

    def test_invalid_severity_enum_rejected(self):
        f = _well_formed_strict_finding(severity="catastrophic")
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_invalid_status_enum_rejected(self):
        f = _well_formed_strict_finding(status="MAYBE")
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_invalid_confidence_enum_rejected(self):
        # CLAUDE.md is explicit that confidence is high/medium/low, not the
        # match-verdict tokens. Catching "CONFIRMED" as confidence guards
        # against the documented "do not collapse status and confidence"
        # failure mode.
        f = _well_formed_strict_finding(confidence="CONFIRMED")
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_evidence_as_string_rejected(self):
        # CLAUDE.md requires evidence to be an object, not a string
        f = _well_formed_strict_finding(evidence="just a string")
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_title_over_100_chars_rejected(self):
        f = _well_formed_strict_finding(title="x" * 101)
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_confirmed_with_empty_tool_attribution_rejected(self):
        f = _well_formed_strict_finding(status="CONFIRMED", tool_attribution=[])
        with self.assertRaises(FindingsSchemaError):
            validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_unconfirmed_with_empty_tool_attribution_allowed(self):
        # The non-empty requirement only applies to CONFIRMED findings.
        f = _well_formed_strict_finding(status="UNCONFIRMED", tool_attribution=[])
        validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_retracted_without_reason_rejected(self):
        f = _well_formed_strict_finding(status="RETRACTED")
        with self.assertRaises(FindingsSchemaError) as ctx:
            validate_findings(_well_formed_strict_doc([f]), strict=True)
        self.assertIn("retraction_reason", str(ctx.exception))

    def test_retracted_with_reason_accepted(self):
        f = _well_formed_strict_finding(
            status="RETRACTED",
            category="false_positive",
            retraction_reason="byte pattern matches CLR heap, not shellcode",
        )
        validate_findings(_well_formed_strict_doc([f]), strict=True)

    def test_run1_old_schema_rejected(self):
        """Strict mode intentionally rejects pre-CLAUDE.md schema runs."""
        with self.assertRaises(FindingsSchemaError):
            validate_findings_file(
                REPO / "cases" / "srl-2018" / "run1_reports" / "findings.json",
                strict=True,
            )

    def test_run6_full_schema_accepted(self):
        """Run 6 was authored to the full CLAUDE.md schema."""
        validate_findings_file(
            REPO / "cases" / "srl-2018" / "run6_reports" / "findings.json",
            strict=True,
        )


class FileLoadingTests(unittest.TestCase):

    def test_invalid_json_raises_schema_error(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{")
            path = f.name
        try:
            with self.assertRaises(FindingsSchemaError) as ctx:
                validate_findings_file(path, strict=False)
            self.assertIn("not valid JSON", str(ctx.exception))
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
