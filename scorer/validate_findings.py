"""
Pre-flight findings-file validator (task item 2).

The scorer accepts findings in two top-level shapes:

  1. Flat array          — `[{...}, {...}, ...]`           (Run 1)
  2. Wrapper object      — `{"findings": [...], ...}`      (Runs 2-6)

Both are valid input to `scorer.scorer.score()`. A single jsonschema
against CLAUDE.md's per-finding schema would fail Run 1 outright; that's
why this validator is schema-aware.

Two modes:

  - `permissive` (default): accept either top-level shape, require only
    the per-finding fields the scorer actually consumes (id, title,
    description). Used as a pre-flight gate inside `score()` so all six
    existing runs continue to validate.
  - `strict`: enforce the full CLAUDE.md per-finding schema. Intended
    for new runs (Run 7+) where the agent prompt mandates the full
    schema. Not called automatically — invoke explicitly when grading
    new runs.

On validation failure, raises `FindingsSchemaError` with a message
identifying the failing path and the rule it violated. Fail loud is the
point — silent degradation to "UNKNOWN" status was the failure mode
this guards against.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

import jsonschema
from jsonschema import Draft7Validator


class FindingsSchemaError(ValueError):
    """A findings file (or in-memory dict/list) failed schema validation."""


# ── Permissive schema ────────────────────────────────────────────────────────
#
# Minimum required for the scorer to function:
#   - id, title, description on every finding
# The scorer is robust to missing severity/status/confidence/category — but it
# silently degrades. We require these three because their absence means the
# finding contributes nothing to scoring beyond noise.

_PERMISSIVE_FINDING = {
    "type": "object",
    "required": ["id", "title", "description"],
    "properties": {
        "id":          {"type": "string", "minLength": 1},
        "title":       {"type": "string", "minLength": 1},
        "description": {"type": "string"},
    },
}

# The permissive contract is "either a flat array of findings, or a wrapper
# object containing a `findings` array". Expressed via jsonschema's `oneOf`
# the top-level error degrades to "not valid under any of the given schemas"
# with the per-finding details swallowed. Instead, we detect the shape in
# code and validate against the appropriate sub-schema directly so that
# per-finding error messages survive.

_PERMISSIVE_FLAT: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "array",
    "items": _PERMISSIVE_FINDING,
}

_PERMISSIVE_WRAPPED: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": _PERMISSIVE_FINDING,
        },
    },
}

# Kept for callers that want a single jsonschema document (e.g. for export).
PERMISSIVE_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "SIFT-Bench findings file (permissive)",
    "oneOf": [_PERMISSIVE_FLAT, _PERMISSIVE_WRAPPED],
}


# ── Strict schema (CLAUDE.md "Output Schema Requirements") ───────────────────
#
# Enforces the per-finding contract CLAUDE.md spells out for new runs:
#   id, title, description, severity, status, confidence, category,
#   evidence (object), tool_attribution (array)
# Plus the conditional rule: retraction_reason required if status=RETRACTED.

_STRICT_FINDING = {
    "type": "object",
    "required": [
        "id", "title", "description",
        "severity", "status", "confidence", "category",
        "evidence", "tool_attribution",
    ],
    "properties": {
        "id":          {"type": "string", "minLength": 1},
        "title":       {"type": "string", "minLength": 1, "maxLength": 200},
        "description": {"type": "string", "minLength": 1},
        "severity":    {"enum": ["critical", "high", "medium", "low"]},
        "status":      {"enum": ["CONFIRMED", "UNCONFIRMED", "RETRACTED"]},
        "confidence":  {"enum": ["high", "medium", "low"]},
        "category":    {"enum": [
            "malware", "lateral_movement", "c2", "credential_access",
            "persistence", "discovery", "execution", "defense_evasion",
            "exfiltration", "false_positive", "synthesis", "other",
        ]},
        "evidence":          {"type": "object"},
        "tool_attribution":  {"type": "array", "items": {"type": "string"}},
        "mitre_attack":      {"type": "array", "items": {"type": "string"}},
        "retraction_reason": {"type": "string"},
    },
    "allOf": [
        {
            # retraction_reason required when status=RETRACTED
            "if":   {"properties": {"status": {"const": "RETRACTED"}}},
            "then": {"required": ["retraction_reason"]},
        },
    ],
}

STRICT_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "SIFT-Bench findings file (strict, CLAUDE.md schema)",
    "type": "object",
    "required": [
        "case_id", "analyst", "evidence_image",
        "analysis_timestamp_utc", "phase", "findings", "summary",
    ],
    "properties": {
        "case_id":                {"type": "string"},
        "analyst":                {"type": "string"},
        "evidence_image":         {"type": "string"},
        "analysis_timestamp_utc": {"type": "string"},
        "phase":                  {"enum": ["pre_correction", "post_correction"]},
        "findings": {
            "type": "array",
            "items": _STRICT_FINDING,
        },
        "summary": {
            "type": "object",
            "required": [
                "total_findings", "confirmed_count",
                "unconfirmed_count", "retracted_count",
            ],
            "properties": {
                "total_findings":     {"type": "integer", "minimum": 0},
                "confirmed_count":    {"type": "integer", "minimum": 0},
                "unconfirmed_count":  {"type": "integer", "minimum": 0},
                "retracted_count":    {"type": "integer", "minimum": 0},
            },
        },
    },
}


# ── Validation API ──────────────────────────────────────────────────────────

def _format_error(err: jsonschema.ValidationError) -> str:
    path = "/" + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
    return f"at {path}: {err.message}"


def _select_permissive_subschema(data: Any) -> dict:
    """Pick the permissive sub-schema that matches `data`'s top-level shape.

    Returns the sub-schema dict (flat-array or wrapper-object). Raises
    FindingsSchemaError if the top-level shape is neither.
    """
    if isinstance(data, list):
        return _PERMISSIVE_FLAT
    if isinstance(data, dict) and "findings" in data:
        return _PERMISSIVE_WRAPPED
    raise FindingsSchemaError(
        "Findings document failed permissive schema validation: "
        "at (root): must be either a flat array of findings, or an object "
        "containing a `findings` array (got "
        f"{type(data).__name__})"
    )


def validate_findings(
    data: Union[list, dict],
    *,
    strict: bool = False,
) -> None:
    """Validate a findings document already parsed into Python.

    Raises FindingsSchemaError with a concrete path + rule on failure.
    """
    if strict:
        schema = STRICT_SCHEMA
        mode = "strict"
    else:
        schema = _select_permissive_subschema(data)
        mode = "permissive"

    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        msgs = "; ".join(_format_error(e) for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise FindingsSchemaError(
            f"Findings document failed {mode} schema validation: {msgs}{more}"
        )


def validate_findings_file(path: Union[str, Path], *, strict: bool = False) -> None:
    """Read `path` and validate the contents. Useful as a CLI pre-flight."""
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise FindingsSchemaError(f"{p}: not valid JSON: {e}") from e
    try:
        validate_findings(data, strict=strict)
    except FindingsSchemaError as e:
        raise FindingsSchemaError(f"{p}: {e}") from e


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Validate a SIFT-Bench findings JSON file."
    )
    parser.add_argument("path", help="Path to findings*.json")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce full CLAUDE.md schema (use for new runs).",
    )
    args = parser.parse_args()

    try:
        validate_findings_file(args.path, strict=args.strict)
    except FindingsSchemaError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)

    mode = "strict" if args.strict else "permissive"
    print(f"OK: {args.path} validates against {mode} schema.")
