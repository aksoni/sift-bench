"""
SIFT-Bench scorer: weighted F1 against ground truth.

Inputs:
  - ground_truth_path: path to base-rd01-v1.1.json (ground truth)
  - findings_path: path to findings_post_correction.json from agent run

Output: dict with weighted_f1, precision, recall, per-finding results,
        FP traps caught, negative assertions caught, missed findings.

Usage:
  python scorer.py <ground_truth.json> <findings_post_correction.json>
"""

import json
import sys
from pathlib import Path


def load_json(p):
    return json.loads(Path(p).read_text())


def normalize_findings(raw):
    """Handle schema drift: accept flat array or wrapped object."""
    if isinstance(raw, dict) and "findings" in raw:
        return raw["findings"]
    if isinstance(raw, list):
        return raw
    raise ValueError(f"Unknown findings schema: {type(raw)}")


def get_text(finding):
    """Extract searchable text from a finding, handling schema variants."""
    parts = []
    for key in ("title", "description", "tool_output", "evidence"):
        val = finding.get(key, "")
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, list):
            parts.append(" ".join(str(v) for v in val))
        elif isinstance(val, dict):
            parts.append(json.dumps(val))
    return " ".join(parts).lower()


def get_status(finding):
    """Extract the classification status, handling both schema variants."""
    # Run 2 style: separate status field
    status = finding.get("status", "")
    if status.upper() in ("CONFIRMED", "UNCONFIRMED", "RETRACTED"):
        return status.upper()
    # Run 1 style: confidence field doubles as status
    conf = finding.get("confidence", "")
    if conf.upper() in ("CONFIRMED", "UNCONFIRMED", "RETRACTED"):
        return conf.upper()
    return "UNKNOWN"


def extract_keywords(gt_finding):
    """Pull distinctive identifiers from a ground truth finding's evidence."""
    keywords = set()
    ev = gt_finding.get("evidence", {})
    if isinstance(ev, dict):
        _extract_from_dict(ev, keywords)
    # Also pull PIDs and process names from the title/description
    title = gt_finding.get("title", "").lower()
    desc = gt_finding.get("description", "").lower()
    for text in (title, desc):
        for token in text.split():
            # Keep PID numbers, IP addresses, file paths, process names
            if any(c.isdigit() for c in token) and len(token) >= 3:
                keywords.add(token.strip(".,;:()"))
    return sorted(keywords)[:15]


def _extract_from_dict(d, keywords):
    """Recursively extract string/int values from evidence dicts."""
    for k, v in d.items():
        if isinstance(v, str) and len(v) > 3 and v.lower() not in ("none", "null", "true", "false"):
            keywords.add(v.lower().strip())
        elif isinstance(v, (int, float)):
            keywords.add(str(v))
        elif isinstance(v, dict):
            _extract_from_dict(v, keywords)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str) and len(item) > 3:
                    keywords.add(item.lower().strip())
                elif isinstance(item, dict):
                    _extract_from_dict(item, keywords)


def match_finding(gt_finding, agent_findings):
    """
    Check if any agent finding matches a ground truth finding.
    Uses keyword overlap from evidence fields + title/description.
    Returns the matching agent finding or None.
    """
    gt_keywords = extract_keywords(gt_finding)
    gt_title_words = set(gt_finding.get("title", "").lower().split())

    # Also add the finding's category-specific identifiers
    category = gt_finding.get("category", "")
    gt_id = gt_finding.get("id", "")

    best_match = None
    best_score = 0

    for af in agent_findings:
        af_text = get_text(af)

        # Count keyword matches
        kw_matches = sum(1 for kw in gt_keywords if kw in af_text)

        # Count title word overlap (excluding common words)
        af_title_words = set(af.get("title", "").lower().split())
        common_words = {"the", "a", "an", "in", "to", "of", "and", "for", "is", "was", "not", "no", "from", "via", "with"}
        title_overlap = len((gt_title_words - common_words) & (af_title_words - common_words))

        score = kw_matches + title_overlap

        # Special cases: persistence negative finding
        if category == "persistence" and "persistence" not in gt_finding.get("title", "").lower():
            pass
        if "no" in gt_finding.get("title", "").lower() and "persistence" in gt_finding.get("title", "").lower():
            # For negative persistence finding, look for explicit absence reporting
            if "no" in af_text and "persistence" in af_text:
                score += 3
            elif "persistence" in af_text and ("not detected" in af_text or "not found" in af_text or "absence" in af_text or "negative" in af_text):
                score += 3

        # Special case: false_positive category findings (F010)
        if category == "false_positive":
            # Check if agent retracted this or classified as FP
            pid = str(gt_finding.get("evidence", {}).get("pid", ""))
            process = gt_finding.get("evidence", {}).get("process_name", gt_finding.get("title", "")).lower()
            if pid in af_text and ("retract" in af_text or "false positive" in af_text or "benign" in af_text or "clr" in af_text):
                score += 3

        if score >= 2 and (
            score > best_score
            or (score == best_score and best_match is not None
                and af.get("id", "") < best_match.get("id", ""))
        ):
            best_score = score
            best_match = af

    return best_match, best_score


def check_fp_retracted(fp_trap, agent_findings):
    """Check if the agent correctly retracted a false positive trap."""
    process_name = fp_trap.get("process_name", "").lower()
    pid = str(fp_trap.get("pid", ""))

    for af in agent_findings:
        af_text = get_text(af)
        status = get_status(af)

        # Must mention the process and be RETRACTED
        if process_name in af_text and status == "RETRACTED":
            return True
        # Also check for explicit "false positive" language
        if process_name in af_text and "false positive" in af_text:
            return True
        if pid in af_text and (status == "RETRACTED" or "false positive" in af_text):
            return True

    return False


def check_na_addressed(na, agent_findings):
    """Check if the agent addressed a negative assertion."""
    na_title = na.get("title", "").lower()
    verdict = na.get("verdict", "").upper()

    # Extract meaningful words from the NA title
    common_words = {"the", "a", "an", "in", "to", "of", "and", "for", "is", "was", "this", "that", "host"}
    na_words = [w for w in na_title.split() if w not in common_words and len(w) > 3]

    for af in agent_findings:
        af_text = get_text(af)

        # Count how many NA-specific words appear
        matches = sum(1 for w in na_words if w in af_text)

        if matches >= 2:
            # For FALSE assertions: agent should NOT claim it's true
            # For UNVERIFIED: agent should not claim it without evidence
            status = get_status(af)

            if verdict == "FALSE":
                # Agent should retract or explicitly state it's not the case
                if status == "RETRACTED" or "false positive" in af_text or "not " in af_text or "no " in af_text or "absence" in af_text or "negative" in af_text:
                    return True
            elif verdict == "UNVERIFIED":
                # Agent should not claim this with certainty
                if status != "CONFIRMED":
                    return True

    return False


def score(gt_path, findings_path):
    """Score agent findings against ground truth. Returns results dict."""
    gt = load_json(gt_path)
    agent_findings = normalize_findings(load_json(findings_path))
    weights = gt.get("severity_weights", {"critical": 4, "high": 2, "medium": 1, "low": 0.5})

    results = {
        "findings_matched": [],
        "findings_missed": [],
        "fp_traps_caught": [],
        "fp_traps_missed": [],
        "na_caught": [],
        "na_missed": [],
        "weighted_tp": 0.0,
        "weighted_fn": 0.0,
        "agent_finding_count": len(agent_findings),
    }

    # Score each ground truth finding
    # Process higher-weight findings first so they win contested agent findings.
    claimed = set()  # object ids of agent findings already matched
    gt_findings_by_weight = sorted(
        gt["findings"],
        key=lambda f: weights.get(f.get("severity", "medium"), 1),
        reverse=True,
    )
    for gt_f in gt_findings_by_weight:
        severity = gt_f.get("severity", "medium")
        weight = weights.get(severity, 1)
        fid = gt_f["id"]
        category = gt_f.get("category", "")

        available = [af for af in agent_findings if id(af) not in claimed]
        match, match_score = match_finding(gt_f, available)

        if match:
            claimed.add(id(match))
            results["findings_matched"].append({
                "gt_id": fid,
                "gt_title": gt_f["title"],
                "severity": severity,
                "weight": weight,
                "matched_to": match.get("id", match.get("title", "unknown")[:50]),
                "match_score": match_score,
                "must_find": gt_f.get("must_find", False),
            })
            results["weighted_tp"] += weight
        else:
            results["findings_missed"].append({
                "gt_id": fid,
                "gt_title": gt_f["title"],
                "severity": severity,
                "weight": weight,
                "must_find": gt_f.get("must_find", False),
            })
            results["weighted_fn"] += weight

    # Score FP traps
    for fp in gt.get("false_positive_traps", []):
        if check_fp_retracted(fp, agent_findings):
            results["fp_traps_caught"].append(fp["id"])
        else:
            results["fp_traps_missed"].append(fp["id"])

    # Score negative assertions
    for na in gt.get("negative_assertions", []):
        if check_na_addressed(na, agent_findings):
            results["na_caught"].append(na["id"])
        else:
            results["na_missed"].append(na["id"])

    # Compute metrics
    total_weight = results["weighted_tp"] + results["weighted_fn"]
    results["weighted_recall"] = round(results["weighted_tp"] / total_weight, 4) if total_weight > 0 else 0.0

    # Precision stub: 1.0 for now (needs LLM-as-judge to check false claims)
    results["weighted_precision"] = 1.0  # TODO: LLM-as-judge

    p = results["weighted_precision"]
    r = results["weighted_recall"]
    results["weighted_f1"] = round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0

    # Summary stats
    results["must_find_hit"] = sum(1 for m in results["findings_matched"] if m["must_find"])
    results["must_find_total"] = sum(1 for f in gt["findings"] if f.get("must_find", False))
    results["must_find_missed"] = [m["gt_id"] for m in results["findings_missed"] if m["must_find"]]

    return results


def print_report(results):
    """Pretty-print the scoring results."""
    print("=" * 60)
    print("SIFT-BENCH SCORING REPORT")
    print("=" * 60)

    print(f"\n--- Weighted F1: {results['weighted_f1']:.4f} ---")
    print(f"    Precision: {results['weighted_precision']:.4f} (stub — needs LLM-as-judge)")
    print(f"    Recall:    {results['weighted_recall']:.4f}")

    print(f"\nMust-find critical findings: {results['must_find_hit']}/{results['must_find_total']}")
    if results["must_find_missed"]:
        print(f"  MISSED: {results['must_find_missed']}")

    print(f"\nFindings matched: {len(results['findings_matched'])}/{len(results['findings_matched']) + len(results['findings_missed'])}")
    for m in results["findings_matched"]:
        marker = " *" if m["must_find"] else ""
        print(f"  ✓ {m['gt_id']} ({m['severity']}){marker}: {m['gt_title'][:60]}")
        print(f"    → matched to: {m['matched_to']}  [score={m['match_score']}]")

    if results["findings_missed"]:
        print(f"\nFindings missed: {len(results['findings_missed'])}")
        for m in results["findings_missed"]:
            marker = " * CRITICAL" if m["must_find"] else ""
            print(f"  ✗ {m['gt_id']} ({m['severity']}){marker}: {m['gt_title'][:60]}")

    print(f"\nFP traps caught: {len(results['fp_traps_caught'])}/{len(results['fp_traps_caught']) + len(results['fp_traps_missed'])}")
    for fp in results["fp_traps_caught"]:
        print(f"  ✓ {fp}")
    for fp in results["fp_traps_missed"]:
        print(f"  ✗ {fp}")

    print(f"\nNegative assertions addressed: {len(results['na_caught'])}/{len(results['na_caught']) + len(results['na_missed'])}")
    for na in results["na_caught"]:
        print(f"  ✓ {na}")
    for na in results["na_missed"]:
        print(f"  ✗ {na}")

    print(f"\nAgent produced {results['agent_finding_count']} total findings")
    print(f"Weighted TP: {results['weighted_tp']}, Weighted FN: {results['weighted_fn']}")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scorer.py <ground_truth.json> <findings.json>")
        sys.exit(1)

    results = score(sys.argv[1], sys.argv[2])
    print_report(results)
    # Also dump raw JSON for programmatic use
    print("\n--- RAW JSON ---")
    print(json.dumps(results, indent=2))
