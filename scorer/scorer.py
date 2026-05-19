"""
SIFT-Bench scorer v0.4: weighted F1 against ground truth.
match_finding now uses LLM-as-judge (judge_pair) instead of keyword-only scoring.
Precision remains stubbed at 1.0 (v0.5 scope).
"""

import json
import logging
import sys
from pathlib import Path

import anthropic

from .judge import JudgeApiError, judge_pair
from .judge_cache import JudgeCache, JudgeVerdict

MODEL_SNAPSHOT = "claude-sonnet-4-6"


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
    status = finding.get("status", "")
    if status.upper() in ("CONFIRMED", "UNCONFIRMED", "RETRACTED"):
        return status.upper()
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
    title = gt_finding.get("title", "").lower()
    desc = gt_finding.get("description", "").lower()
    for text in (title, desc):
        for token in text.split():
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


def match_finding(
    gt_finding,
    agent_findings,
    *,
    cache: JudgeCache,
    client: anthropic.Anthropic,
    model_snapshot: str,
    prompt_template: str,
) -> "tuple[dict | None, JudgeVerdict | None]":
    """
    Find the best-matching agent finding for a GT finding using LLM-as-judge.

    Pre-filters to top-3 by keyword overlap, then asks the judge for each in
    order (pre-filter score desc, agent_id lex asc). First candidate with
    verdict.match=True and confidence>=4 wins.

    FP traps and persistence negatives are handled in score() via separate
    check_fp_retracted / check_na_addressed calls — not here. (Deleted from
    v0.3 to avoid double-counting and unreachable branches.)
    """
    gt_keywords = extract_keywords(gt_finding)
    gt_title_words = set(gt_finding.get("title", "").lower().split())
    common_words = {
        "the", "a", "an", "in", "to", "of", "and", "for", "is", "was",
        "not", "no", "from", "via", "with",
    }

    # Pre-filter: score every candidate by keyword overlap
    scored = []
    for af in agent_findings:
        af_text = get_text(af)
        kw_matches = sum(1 for kw in gt_keywords if kw in af_text)
        af_title_words = set(af.get("title", "").lower().split())
        title_overlap = len((gt_title_words - common_words) & (af_title_words - common_words))
        score = kw_matches + title_overlap
        if score > 0:
            scored.append((score, af))

    # Top-K=3: deterministic order — pre-filter score desc, agent_id lex asc
    top3 = sorted(scored, key=lambda x: (-x[0], x[1].get("id", "")))[:3]

    for prefilter_score, af in top3:
        verdict = judge_pair(
            gt_finding,
            af,
            cache=cache,
            client=client,
            model_snapshot=model_snapshot,
            prompt_template=prompt_template,
        )
        if verdict.match and verdict.confidence >= 4:
            return af, verdict
        if verdict.confidence == 3:
            logging.warning(
                "Low-confidence verdict (3) for %s / %s — not matched",
                gt_finding.get("id"), af.get("id"),
            )

    return None, None


def check_fp_retracted(fp_trap, agent_findings):
    """Check if the agent correctly retracted a false positive trap."""
    process_name = fp_trap.get("process_name", "").lower()
    pid = str(fp_trap.get("pid", ""))

    for af in agent_findings:
        af_text = get_text(af)
        status = get_status(af)

        if process_name in af_text and status == "RETRACTED":
            return True
        if process_name in af_text and "false positive" in af_text:
            return True
        if pid in af_text and (status == "RETRACTED" or "false positive" in af_text):
            return True

    return False


def check_na_addressed(na, agent_findings):
    """Check if the agent addressed a negative assertion."""
    na_title = na.get("title", "").lower()
    verdict = na.get("verdict", "").upper()

    common_words = {"the", "a", "an", "in", "to", "of", "and", "for", "is", "was", "this", "that", "host"}
    na_words = [w for w in na_title.split() if w not in common_words and len(w) > 3]

    for af in agent_findings:
        af_text = get_text(af)
        matches = sum(1 for w in na_words if w in af_text)
        if matches >= 2:
            status = get_status(af)
            if verdict == "FALSE":
                if status == "RETRACTED" or "false positive" in af_text or "not " in af_text or "no " in af_text or "absence" in af_text or "negative" in af_text:
                    return True
            elif verdict == "UNVERIFIED":
                if status != "CONFIRMED":
                    return True

    return False


def score(gt_path, findings_path):
    """Score agent findings against ground truth. Returns results dict."""
    gt = load_json(gt_path)
    agent_findings = normalize_findings(load_json(findings_path))
    weights = gt.get("severity_weights", {"critical": 4, "high": 2, "medium": 1, "low": 0.5})

    prompt_template = (Path(__file__).parent / "prompts" / "judge_v0.4.txt").read_text()
    client = anthropic.Anthropic()
    cache = JudgeCache()

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

    claimed = set()
    gt_findings_by_weight = sorted(
        gt["findings"],
        key=lambda f: weights.get(f.get("severity", "medium"), 1),
        reverse=True,
    )

    try:
        for gt_f in gt_findings_by_weight:
            severity = gt_f.get("severity", "medium")
            weight = weights.get(severity, 1)
            fid = gt_f["id"]

            available = [af for af in agent_findings if id(af) not in claimed]
            match, verdict = match_finding(
                gt_f,
                available,
                cache=cache,
                client=client,
                model_snapshot=MODEL_SNAPSHOT,
                prompt_template=prompt_template,
            )

            if match:
                claimed.add(id(match))
                results["findings_matched"].append({
                    "gt_id": fid,
                    "gt_title": gt_f["title"],
                    "severity": severity,
                    "weight": weight,
                    "matched_to": match.get("id", match.get("title", "unknown")[:50]),
                    "judge_confidence": verdict.confidence,
                    "judge_reasoning": verdict.reasoning,
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
    except JudgeApiError:
        cache.save()
        raise
    finally:
        cache.save()

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

    total_weight = results["weighted_tp"] + results["weighted_fn"]
    results["weighted_recall"] = round(results["weighted_tp"] / total_weight, 4) if total_weight > 0 else 0.0

    # Precision stub: 1.0 for now (needs LLM-as-judge to check false claims)
    results["weighted_precision"] = 1.0  # TODO: LLM-as-judge v0.5

    p = results["weighted_precision"]
    r = results["weighted_recall"]
    results["weighted_f1"] = round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0

    results["must_find_hit"] = sum(1 for m in results["findings_matched"] if m["must_find"])
    results["must_find_total"] = sum(1 for f in gt["findings"] if f.get("must_find", False))
    results["must_find_missed"] = [m["gt_id"] for m in results["findings_missed"] if m["must_find"]]

    return results


def print_report(results):
    """Pretty-print the scoring results."""
    print("=" * 60)
    print("SIFT-BENCH SCORING REPORT (v0.4 — LLM-as-judge)")
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
        print(f"    → matched to: {m['matched_to']}  [judge_confidence={m['judge_confidence']}]")

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
