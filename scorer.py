"""Root CLI entrypoint. Implementation lives in scorer/scorer.py (v0.4)."""
import argparse
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path so the 'scorer' package resolves correctly
sys.path.insert(0, str(Path(__file__).parent))

from scorer.scorer import print_report, score

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIFT-Bench scorer")
    parser.add_argument("ground_truth", help="Ground truth JSON path")
    parser.add_argument("findings", help="Agent findings JSON path (post-correction)")
    parser.add_argument("--log", metavar="PATH", help="execution_log.json for checklist scoring")
    parser.add_argument("--pre", metavar="PATH", help="findings_pre_correction.json for self-correction scoring")
    args = parser.parse_args()

    results = score(args.ground_truth, args.findings,
                    log_path=args.log, pre_correction_path=args.pre)
    print_report(results)
    print("\n--- RAW JSON ---")
    print(json.dumps(results, indent=2))
