"""v0.5 re-scoring orchestrator. Scores all 6 runs, writes per-run JSON, prints summary."""
import json
import os
import sys
from pathlib import Path

ROOT = Path("/home/abhisoni/sift-bench")
sys.path.insert(0, str(ROOT))
from scorer.scorer import score  # noqa: E402

GT = str(ROOT / "ground_truth/base-rd01-v1.1.json")
OUT = ROOT / "analysis/v05_rescoring"
OUT.mkdir(parents=True, exist_ok=True)


def run_dir(n):
    return ROOT / f"cases/srl-2018/run{n}_analysis"


def find_f006(results):
    """Return (matched_bool, via_fallback_value) for GT F006."""
    for m in results.get("findings_matched", []):
        if m.get("gt_id") == "F006":
            return True, m.get("via_fallback", None)
    return False, None


def scalar_keys(d):
    return {k: v for k, v in d.items() if isinstance(v, (int, float, str, bool)) or v is None}


summary = {}
for n in range(1, 7):
    d = run_dir(n)
    post = d / "findings_post_correction.json"
    log = d / "execution_log.json"
    pre = d / "findings_pre_correction.json"
    log_path = str(log) if log.exists() else None
    pre_path = str(pre) if pre.exists() else None

    print(f"=== Scoring run{n} (log={'Y' if log_path else 'N'}, pre={'Y' if pre_path else 'N'}) ===",
          flush=True)
    res = score(GT, str(post), log_path=log_path, pre_correction_path=pre_path)

    with open(OUT / f"run{n}_score.json", "w") as f:
        json.dump(res, f, indent=2)

    f006_matched, f006_via_fb = find_f006(res)
    summary[f"run{n}"] = {
        "scalars": scalar_keys(res),
        "n_matched": len(res.get("findings_matched", [])),
        "n_missed": len(res.get("findings_missed", [])),
        "must_find": f"{res.get('must_find_hit')}/{res.get('must_find_total')}",
        "must_find_missed": res.get("must_find_missed"),
        "fp_traps_caught": len(res.get("fp_traps_caught", [])),
        "fp_traps_total": len(res.get("fp_traps_caught", [])) + len(res.get("fp_traps_missed", [])),
        "na_caught": len(res.get("na_caught", [])),
        "f006_matched": f006_matched,
        "f006_via_fallback": f006_via_fb,
        "log_used": bool(log_path),
        "pre_used": bool(pre_path),
    }
    print(json.dumps(summary[f"run{n}"], indent=2, default=str), flush=True)

with open(OUT / "summary.json", "w") as f:
    json.dump(summary, f, indent=2, default=str)

print("\n===== CONSOLIDATED =====", flush=True)
hdr = f"{'run':>4} {'recall':>8} {'precision':>10} {'f1':>8} {'must':>6} {'fp':>5} {'F006':>6} {'viaFB':>6}"
print(hdr, flush=True)
for n in range(1, 7):
    s = summary[f"run{n}"]
    sc = s["scalars"]
    print(f"{n:>4} {sc.get('weighted_recall',0):>8.4f} {sc.get('weighted_precision',0):>10.4f} "
          f"{sc.get('weighted_f1',0):>8.4f} {s['must_find']:>6} "
          f"{s['fp_traps_caught']}/{s['fp_traps_total']:>3} {str(s['f006_matched']):>6} "
          f"{str(s['f006_via_fallback']):>6}", flush=True)
print("\nAll top-level scalar keys present in run1 result:", flush=True)
print(sorted(summary['run1']['scalars'].keys()), flush=True)
print("DONE", flush=True)
