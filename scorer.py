"""Root CLI entrypoint. Implementation lives in scorer/scorer.py (v0.4)."""
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path so the 'scorer' package resolves correctly
sys.path.insert(0, str(Path(__file__).parent))

from scorer.scorer import print_report, score

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scorer.py <ground_truth.json> <findings.json>")
        sys.exit(1)

    results = score(sys.argv[1], sys.argv[2])
    print_report(results)
    print("\n--- RAW JSON ---")
    print(json.dumps(results, indent=2))
