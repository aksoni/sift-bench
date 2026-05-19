"""Regression test suite for scorer v0.4 LLM-as-judge prompt.

Runs the three locked test cases from design/judge_test_cases.json against
judge_pair(), then reruns them to verify cache-hit determinism.
Exit 0 = all pass. Exit 1 = any failure.
"""
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path for 'scorer' package imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic
from scorer.judge import JudgeParseError, judge_pair
from scorer.judge_cache import JudgeCache

# Must match design/scorer-v0.4.md § Pinned Model Snapshot
MODEL_SNAPSHOT = "claude-sonnet-4-6"


def main():
    project_root = Path(__file__).parent.parent
    test_cases_path = project_root / "design" / "judge_test_cases.json"
    prompt_path = project_root / "scorer" / "prompts" / "judge_v0.4.txt"
    cache_path = project_root / "scorer_cache" / "judge_verdicts.json"

    test_data = json.loads(test_cases_path.read_text())
    prompt_template = prompt_path.read_text()
    test_cases = test_data["test_cases"]

    cache = JudgeCache(cache_path)
    client = anthropic.Anthropic()

    print(f"Running {len(test_cases)} test cases against {MODEL_SNAPSHOT}...")
    all_passed = True
    first_verdicts = []

    # Step 4 (validate_judge step 1-4): run each case and check verdict
    for tc in test_cases:
        tc_id = tc["test_id"]
        expected = tc["expected_verdict"]

        verdict = judge_pair(
            tc["ground_truth_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            prompt_template=prompt_template,
        )
        first_verdicts.append(verdict)

        failures = []

        if verdict.match != expected["match"]:
            failures.append(
                f"match: got {verdict.match}, expected {expected['match']}"
            )

        if verdict.confidence < expected["confidence_min"]:
            failures.append(
                f"confidence: got {verdict.confidence}, expected >= {expected['confidence_min']}"
            )

        reasoning_lower = verdict.reasoning.lower()
        phrase_hit = any(
            phrase.lower() in reasoning_lower
            for phrase in expected["reasoning_must_reference"]
        )
        if not phrase_hit:
            failures.append(
                f"reasoning did not reference any of: {expected['reasoning_must_reference']}"
            )

        if failures:
            print(f"  FAIL {tc_id}: {'; '.join(failures)}")
            print(f"    reasoning: {verdict.reasoning}")
            all_passed = False
        else:
            print(
                f"  PASS {tc_id}: match={verdict.match}, confidence={verdict.confidence}"
            )
            print(f"    reasoning: {verdict.reasoning[:120]}")

    if not all_passed:
        print("\nFAILED: one or more test cases did not pass. Iterate the prompt.")
        cache.save()
        sys.exit(1)

    # Step 6 (validate_judge step 5): rerun for cache-determinism check
    print(f"\nRerunning {len(test_cases)} cases for cache-determinism check...")
    cache_len_before = len(cache)

    for tc, first_verdict in zip(test_cases, first_verdicts):
        tc_id = tc["test_id"]
        second_verdict = judge_pair(
            tc["ground_truth_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            prompt_template=prompt_template,
        )

        if (
            second_verdict.match != first_verdict.match
            or second_verdict.confidence != first_verdict.confidence
            or second_verdict.reasoning != first_verdict.reasoning
        ):
            print(
                f"  FAIL {tc_id}: second-run verdict differs from first (cache miss or non-determinism)"
            )
            cache.save()
            sys.exit(1)

        print(f"  PASS {tc_id}: cache hit, verdict identical")

    if len(cache) != cache_len_before:
        print(
            f"FAIL: cache grew during rerun ({cache_len_before} -> {len(cache)}), "
            "indicating new API calls were made"
        )
        cache.save()
        sys.exit(1)

    print(f"\nAll {len(test_cases)} test cases passed. Cache size: {len(cache)} entries.")
    cache.save()


if __name__ == "__main__":
    main()
