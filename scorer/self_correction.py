"""
Self-correction effectiveness scorer — scorer/self_correction.py

Diffs pre-correction and post-correction findings JSON to produce a
quantified self-correction effectiveness report:

  - findings_retracted: findings that moved to status=RETRACTED in post
  - findings_added:     findings present in post but absent from pre (by id)
  - additions_tp:       added findings that keyword-overlap a ground truth finding
  - additions_fp:       added findings that do not overlap any GT finding
  - fp_traps_retracted: FP trap patterns (FP001-FP003) retracted at correction
  - pre_count / post_count: total finding counts (including RETRACTED)
  - net_change: post_confirmed_count - pre_confirmed_count

F1_delta (pre vs post) is NOT computed automatically — it requires a full
judge pass against pre-correction findings. Run:
  python scorer.py ground_truth/base-rd01-v1.1.json <run>_analysis/findings_pre_correction.json
to get the pre-correction F1; the post-correction F1 is in <run>_score.json.

Known FP trap patterns (from ground truth v1.1):
  FP001: Outlook dtrR — "outlook" + ("dtrr" or "injection")
  FP002: McAfee UpdaterUI — "updaterui" or "mcafee"
  FP003: PowerShell CLR heap — ("clr" or "0xffeeffe" or "0xeeffee") + "powershell"
"""

import json
import re
from pathlib import Path

# ── FP trap keyword patterns ──────────────────────────────────────────────────

FP_TRAP_PATTERNS: list[dict] = [
    {
        "id": "FP001",
        "name": "Outlook dtrR injection false positive",
        "match": lambda text: (
            "outlook" in text and ("dtrr" in text or "injection" in text)
        ),
    },
    {
        "id": "FP002",
        "name": "McAfee UpdaterUI false positive",
        "match": lambda text: (
            "updaterui" in text or "mcafee" in text
        ),
    },
    {
        "id": "FP003",
        "name": "PowerShell CLR heap false positive",
        "match": lambda text: (
            ("clr" in text or "0xffeeffe" in text or "0xeeffee" in text
             or "ffeeffee" in text)
            and "powershell" in text
        ),
    },
]


# ── Schema normalisation ──────────────────────────────────────────────────────

def _extract_findings(data: dict | list) -> list[dict]:
    """Return a flat list of finding dicts from either schema variant."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "findings_post_correction", "findings_pre_correction"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Fallback: any key whose value is a list of dicts with an 'id' field
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and "id" in v[0]:
                return v
    return []


def _finding_text(finding: dict) -> str:
    """Produce a normalised lowercase text blob for keyword matching."""
    parts = [
        str(finding.get("id", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("category", "")),
        json.dumps(finding.get("evidence", {})),
    ]
    return " ".join(parts).lower()


def _is_retracted(finding: dict) -> bool:
    status = str(finding.get("status", "")).upper()
    if status == "RETRACTED":
        return True
    # run1 schema: no status field; retraction signalled by title or id prefix
    fid = str(finding.get("id", ""))
    title = str(finding.get("title", "")).upper()
    if fid.upper().startswith("FP") or "FALSE POSITIVE" in title or "RETRACTED" in title:
        return True
    if str(finding.get("category", "")).lower() == "false_positive":
        return True
    return False


def _is_confirmed(finding: dict) -> bool:
    status = str(finding.get("status", "")).upper()
    if status == "CONFIRMED":
        return True
    # run1 schema: no status field; non-retracted findings are effectively confirmed
    if not status and not _is_retracted(finding):
        return True
    return False


def _keyword_overlap(text: str, gt_findings: list[dict]) -> bool:
    """Return True if text shares meaningful keywords with any GT finding."""
    significant = re.findall(r'\b[a-z0-9_]{4,}\b', text)
    significant_set = set(significant) - {
        "with", "that", "this", "from", "have", "been", "were",
        "their", "they", "also", "into", "than", "more", "some",
        "windows", "process", "file", "system", "memory", "analysis",
    }
    for gt in gt_findings:
        gt_text = _finding_text(gt)
        gt_words = set(re.findall(r'\b[a-z0-9_]{4,}\b', gt_text))
        overlap = significant_set & gt_words
        if len(overlap) >= 3:
            return True
    return False


# ── Main scorer function ──────────────────────────────────────────────────────

def score_self_correction(
    pre_path: str | Path,
    post_path: str | Path,
    gt_path: str | Path | None = None,
) -> dict:
    """
    Compare pre- and post-correction findings to quantify self-correction.

    Args:
        pre_path:  path to findings_pre_correction.json
        post_path: path to findings_post_correction.json
        gt_path:   optional path to ground truth JSON (enables tp/fp split)

    Returns a dict with effectiveness metrics.
    """
    pre_path, post_path = Path(pre_path), Path(post_path)

    missing = [str(p) for p in (pre_path, post_path) if not p.exists()]
    if missing:
        return {"error": f"missing files: {missing}"}

    with open(pre_path) as f:
        pre_data = json.load(f)
    with open(post_path) as f:
        post_data = json.load(f)

    pre_findings = _extract_findings(pre_data)
    post_findings = _extract_findings(post_data)

    gt_findings: list[dict] = []
    if gt_path and Path(gt_path).exists():
        with open(gt_path) as f:
            gt_data = json.load(f)
        gt_findings = _extract_findings(gt_data)

    # Index by id
    pre_by_id = {f.get("id"): f for f in pre_findings if f.get("id")}
    post_by_id = {f.get("id"): f for f in post_findings if f.get("id")}

    # ── Retractions ──────────────────────────────────────────────────────────
    retracted_ids = []
    for fid, post_f in post_by_id.items():
        if _is_retracted(post_f):
            pre_f = pre_by_id.get(fid)
            if pre_f is None or not _is_retracted(pre_f):
                retracted_ids.append(fid)
    # Also catch findings present in pre but absent in post (silently removed)
    silent_removals = [fid for fid in pre_by_id if fid not in post_by_id]

    # ── Additions ────────────────────────────────────────────────────────────
    added_ids = [fid for fid in post_by_id if fid not in pre_by_id]
    additions_tp, additions_fp = [], []
    for fid in added_ids:
        finding = post_by_id[fid]
        text = _finding_text(finding)
        if gt_findings and _keyword_overlap(text, gt_findings):
            additions_tp.append(fid)
        else:
            additions_fp.append(fid)

    # ── FP trap retractions ───────────────────────────────────────────────────
    # Count FP trap patterns that are RETRACTED in post — regardless of pre
    # status. The question is: did the agent correctly identify and retract each
    # known FP pattern by the end of the workflow?
    fp_traps_retracted = []
    seen_traps: set[str] = set()
    for post_f in post_findings:
        if not _is_retracted(post_f):
            continue
        text = _finding_text(post_f)
        for trap in FP_TRAP_PATTERNS:
            if trap["id"] not in seen_traps and trap["match"](text):
                fp_traps_retracted.append({
                    "trap_id": trap["id"],
                    "trap_name": trap["name"],
                    "finding_id": post_f.get("id"),
                })
                seen_traps.add(trap["id"])

    # ── Counts ───────────────────────────────────────────────────────────────
    pre_confirmed  = sum(1 for f in pre_findings  if _is_confirmed(f))
    post_confirmed = sum(1 for f in post_findings if _is_confirmed(f))

    return {
        "pre_finding_count":    len(pre_findings),
        "post_finding_count":   len(post_findings),
        "pre_confirmed_count":  pre_confirmed,
        "post_confirmed_count": post_confirmed,
        "net_change":           post_confirmed - pre_confirmed,
        "findings_retracted":   retracted_ids,
        "retracted_count":      len(retracted_ids),
        "silent_removals":      silent_removals,
        "findings_added":       added_ids,
        "added_count":          len(added_ids),
        "additions_tp":         additions_tp,
        "additions_fp":         additions_fp,
        "fp_traps_retracted":   fp_traps_retracted,
        "fp_traps_retracted_count": len(fp_traps_retracted),
        "f1_delta_note": (
            "Not computed automatically. Run scorer on pre-correction findings "
            "to obtain pre-F1; post-F1 is in <run>_score.json."
        ),
        "gt_provided": bool(gt_findings),
    }
