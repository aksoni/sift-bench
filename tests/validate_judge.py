"""Regression test suite for scorer v0.5 judge prompts.

Sections:
  1. Existing judge_pair cases (v0.4 locked verdicts, unchanged)
  2. Collision guard (no API — unit test of content-addressed key functions)
  3. Precision cases (v0.5 locked verdicts — legitimate and hallucinated)
  4. Fallback case (v0.5 locked verdict — same observation, different framing)

Exit 0 = all pass. Exit 1 = any failure.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic
from scorer.judge import JudgeParseError, judge_fallback_pair, judge_pair, judge_precision
from scorer.judge_cache import JudgeCache, make_cache_key, make_precision_cache_key

MODEL_SNAPSHOT = "claude-sonnet-4-6"

# ---------------------------------------------------------------------------
# Locked precision test cases (defined before any API call)
#
# LEGIT_01: cites specific PIDs, child PIDs, timestamps — clearly traceable
#   to pstree / psscan output. Expected: legitimate=True, confidence>=4.
#
# HALL_01: claims Mimikatz credential dump with no PID, path, or tool output
#   cited. Specific claim ("plaintext passwords for all domain users") with
#   zero forensic grounding. Expected: legitimate=False, confidence>=4.
# ---------------------------------------------------------------------------
PRECISION_CASES = [
    {
        "test_id": "PREC_LEGIT_01",
        "agent_finding": {
            "id": "P_LEGIT_01",
            "title": "powershell.exe PID 5848 spawned six rundll32.exe child processes",
            "description": (
                "Six rundll32.exe processes (PIDs 6768, 5452, 5588, 2216, 4108, 8148) were "
                "spawned by powershell.exe PID 5848 between 18:31 and 00:56 UTC. All exited "
                "within seconds. Pattern is consistent with shellcode staging via LOLBin."
            ),
            "evidence": {
                "pid": 5848,
                "process_name": "powershell.exe",
                "child_pids": [6768, 5452, 5588, 2216, 4108, 8148],
            },
        },
        "expected": {
            "legitimate": True,
            "confidence_min": 4,
            "reasoning_must_reference": ["pid", "5848", "traceable", "specific", "artifact"],
        },
    },
    {
        "test_id": "PREC_HALL_01",
        "agent_finding": {
            "id": "P_HALL_01",
            "title": "p.exe used Mimikatz to dump LSASS credentials and exfiltrate them",
            "description": (
                "p.exe executed Mimikatz sekurlsa::logonpasswords against LSASS, obtaining "
                "plaintext passwords for all domain users. Credentials were exfiltrated to "
                "the C2 server at 172.16.4.10:8080. The attacker gained full domain access."
            ),
            "evidence": {},
        },
        "expected": {
            "legitimate": False,
            "confidence_min": 4,
            "reasoning_must_reference": ["mimikatz", "lsass", "unsupported", "fabricat", "no ", "without"],
        },
    },
]

# ---------------------------------------------------------------------------
# Locked fallback test case (defined before any API call)
#
# FALL_01: GT describes six short-lived rundll32 from PS C2 shell. Agent
#   describes the same observation with explicit child PIDs and "LOLBin proxy"
#   framing rather than "shellcode carriers." Should match despite different
#   vocabulary — this is the F006/F06 recovery pattern.
#   Expected: match=True, confidence>=4.
# ---------------------------------------------------------------------------
FALLBACK_CASES = [
    {
        "test_id": "FALL_MATCH_01",
        "gt_finding": {
            "id": "GT_TEST_F006",
            "title": "Six short-lived rundll32.exe instances from PowerShell C2 shell",
            "description": (
                "PowerShell C2 shell (PID 5848) spawned six rundll32.exe child processes "
                "across the intrusion timeline. All exited within seconds, consistent with "
                "LOLBin shellcode staging."
            ),
            "evidence": {"pid": 5848, "process_name": "powershell.exe", "child_count": 6},
        },
        "agent_finding": {
            "id": "AF_TEST_F06",
            "title": "Six rundll32.exe processes spawned by attacker PowerShell as LOLBin proxies",
            "description": (
                "Attacker-controlled powershell.exe (PID 5848) spawned exactly six rundll32.exe "
                "instances (PIDs 6768, 5452, 5588, 2216, 4108, 8148) as LOLBin proxies. "
                "Each process terminated within 30 seconds of creation."
            ),
            "evidence": {"parent_pid": 5848, "child_pids": [6768, 5452, 5588, 2216, 4108, 8148]},
        },
        "expected": {
            "match": True,
            "confidence_min": 4,
            "reasoning_must_reference": ["same", "rundll32", "powershell", "5848", "six"],
        },
    },
]


def run_collision_guard():
    """Unit test: same id, different content must produce distinct cache keys."""
    print("\n--- Collision guard (no API) ---")

    f_a = {"id": "F07", "title": "p.exe DLL inventory", "description": "DLL analysis of p.exe process"}
    f_b = {"id": "F07", "title": "Six rundll32.exe instances", "description": "rundll32 spawned by PS 5848"}
    gt  = {"id": "F006", "title": "Six short-lived rundll32.exe instances"}
    model = MODEL_SNAPSHOT
    prompt = "dummy prompt"

    k1 = make_precision_cache_key(f_a, model, prompt)
    k2 = make_precision_cache_key(f_b, model, prompt)
    if k1 == k2:
        print("  FAIL: precision keys collide — same id / different content produced identical digest")
        return False
    print(f"  PASS: precision keys distinct  ({k1[:16]}... vs {k2[:16]}...)")

    k3 = make_cache_key(gt, f_a, model, prompt)
    k4 = make_cache_key(gt, f_b, model, prompt)
    if k3 == k4:
        print("  FAIL: match keys collide — same (gt_id, agent_id) / different agent content produced identical digest")
        return False
    print(f"  PASS: match keys distinct      ({k3[:16]}... vs {k4[:16]}...)")

    # Same content must produce the same key (stability check)
    k5 = make_precision_cache_key(f_a, model, prompt)
    if k1 != k5:
        print("  FAIL: precision key is not stable — same input produced different digests")
        return False
    print("  PASS: key stability            (same input -> same digest)")

    return True


def run_precision_cases(cache, client, prompt_template):
    print(f"\n--- Precision cases ({len(PRECISION_CASES)} cases) ---")
    all_passed = True
    first_verdicts = []

    for tc in PRECISION_CASES:
        tc_id = tc["test_id"]
        expected = tc["expected"]

        verdict = judge_precision(
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            precision_prompt_template=prompt_template,
        )
        first_verdicts.append(verdict)

        failures = []
        if verdict.legitimate != expected["legitimate"]:
            failures.append(f"legitimate: got {verdict.legitimate}, expected {expected['legitimate']}")
        if verdict.confidence < expected["confidence_min"]:
            failures.append(f"confidence: got {verdict.confidence}, expected >= {expected['confidence_min']}")
        reasoning_lower = verdict.reasoning.lower()
        if not any(p.lower() in reasoning_lower for p in expected["reasoning_must_reference"]):
            failures.append(f"reasoning did not reference any of: {expected['reasoning_must_reference']}")

        if failures:
            print(f"  FAIL {tc_id}: {'; '.join(failures)}")
            print(f"    reasoning: {verdict.reasoning}")
            all_passed = False
        else:
            print(f"  PASS {tc_id}: legitimate={verdict.legitimate}, confidence={verdict.confidence}")
            print(f"    reasoning: {verdict.reasoning[:120]}")

    if not all_passed:
        return False, first_verdicts

    # Cache-determinism rerun
    print(f"  Rerunning {len(PRECISION_CASES)} precision cases for cache-determinism...")
    cache_len_before = len(cache)
    for tc, first_v in zip(PRECISION_CASES, first_verdicts):
        second_v = judge_precision(
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            precision_prompt_template=prompt_template,
        )
        if (second_v.legitimate != first_v.legitimate
                or second_v.confidence != first_v.confidence
                or second_v.reasoning != first_v.reasoning):
            print(f"  FAIL {tc['test_id']}: second-run verdict differs (cache miss or non-determinism)")
            return False, first_verdicts
        print(f"  PASS {tc['test_id']}: cache hit, verdict identical")
    if len(cache) != cache_len_before:
        print(f"  FAIL: cache grew during precision rerun ({cache_len_before} -> {len(cache)})")
        return False, first_verdicts

    return True, first_verdicts


def run_fallback_cases(cache, client, prompt_template):
    print(f"\n--- Fallback cases ({len(FALLBACK_CASES)} cases) ---")
    all_passed = True
    first_verdicts = []

    for tc in FALLBACK_CASES:
        tc_id = tc["test_id"]
        expected = tc["expected"]

        verdict = judge_fallback_pair(
            tc["gt_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            fallback_prompt_template=prompt_template,
        )
        first_verdicts.append(verdict)

        failures = []
        if verdict.match != expected["match"]:
            failures.append(f"match: got {verdict.match}, expected {expected['match']}")
        if verdict.confidence < expected["confidence_min"]:
            failures.append(f"confidence: got {verdict.confidence}, expected >= {expected['confidence_min']}")
        reasoning_lower = verdict.reasoning.lower()
        if not any(p.lower() in reasoning_lower for p in expected["reasoning_must_reference"]):
            failures.append(f"reasoning did not reference any of: {expected['reasoning_must_reference']}")

        if failures:
            print(f"  FAIL {tc_id}: {'; '.join(failures)}")
            print(f"    reasoning: {verdict.reasoning}")
            all_passed = False
        else:
            print(f"  PASS {tc_id}: match={verdict.match}, confidence={verdict.confidence}")
            print(f"    reasoning: {verdict.reasoning[:120]}")

    if not all_passed:
        return False

    # Cache-determinism rerun
    print(f"  Rerunning {len(FALLBACK_CASES)} fallback cases for cache-determinism...")
    cache_len_before = len(cache)
    for tc, first_v in zip(FALLBACK_CASES, first_verdicts):
        second_v = judge_fallback_pair(
            tc["gt_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            fallback_prompt_template=prompt_template,
        )
        if (second_v.match != first_v.match
                or second_v.confidence != first_v.confidence
                or second_v.reasoning != first_v.reasoning):
            print(f"  FAIL {tc['test_id']}: second-run verdict differs (cache miss or non-determinism)")
            return False
        print(f"  PASS {tc['test_id']}: cache hit, verdict identical")
    if len(cache) != cache_len_before:
        print(f"  FAIL: cache grew during fallback rerun ({cache_len_before} -> {len(cache)})")
        return False

    return True


def main():
    project_root = Path(__file__).parent.parent
    test_cases_path = project_root / "design" / "judge_test_cases.json"
    match_prompt_path = project_root / "scorer" / "prompts" / "judge_v0.4.txt"
    precision_prompt_path = project_root / "scorer" / "prompts" / "judge_v0.5_precision.txt"
    fallback_prompt_path = project_root / "scorer" / "prompts" / "judge_v0.5_fallback.txt"
    cache_path = project_root / "scorer_cache" / "judge_verdicts.json"

    test_data = json.loads(test_cases_path.read_text())
    match_prompt = match_prompt_path.read_text()
    precision_prompt = precision_prompt_path.read_text()
    fallback_prompt = fallback_prompt_path.read_text()
    test_cases = test_data["test_cases"]

    cache = JudgeCache(cache_path)
    client = anthropic.Anthropic()
    all_passed = True

    # --- Section 1: existing judge_pair cases ---
    print(f"Running {len(test_cases)} judge_pair cases against {MODEL_SNAPSHOT}...")
    first_verdicts = []
    for tc in test_cases:
        tc_id = tc["test_id"]
        expected = tc["expected_verdict"]

        verdict = judge_pair(
            tc["ground_truth_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            prompt_template=match_prompt,
        )
        first_verdicts.append(verdict)

        failures = []
        if verdict.match != expected["match"]:
            failures.append(f"match: got {verdict.match}, expected {expected['match']}")
        if verdict.confidence < expected["confidence_min"]:
            failures.append(f"confidence: got {verdict.confidence}, expected >= {expected['confidence_min']}")
        reasoning_lower = verdict.reasoning.lower()
        if not any(p.lower() in reasoning_lower for p in expected["reasoning_must_reference"]):
            failures.append(f"reasoning did not reference any of: {expected['reasoning_must_reference']}")

        if failures:
            print(f"  FAIL {tc_id}: {'; '.join(failures)}")
            print(f"    reasoning: {verdict.reasoning}")
            all_passed = False
        else:
            print(f"  PASS {tc_id}: match={verdict.match}, confidence={verdict.confidence}")
            print(f"    reasoning: {verdict.reasoning[:120]}")

    if not all_passed:
        cache.save()
        sys.exit(1)

    print(f"\nRerunning {len(test_cases)} judge_pair cases for cache-determinism...")
    cache_len_before = len(cache)
    for tc, first_v in zip(test_cases, first_verdicts):
        tc_id = tc["test_id"]
        second_v = judge_pair(
            tc["ground_truth_finding"],
            tc["agent_finding"],
            cache=cache,
            client=client,
            model_snapshot=MODEL_SNAPSHOT,
            prompt_template=match_prompt,
        )
        if (second_v.match != first_v.match
                or second_v.confidence != first_v.confidence
                or second_v.reasoning != first_v.reasoning):
            print(f"  FAIL {tc_id}: second-run verdict differs")
            cache.save()
            sys.exit(1)
        print(f"  PASS {tc_id}: cache hit, verdict identical")
    if len(cache) != cache_len_before:
        print(f"FAIL: cache grew during rerun ({cache_len_before} -> {len(cache)})")
        cache.save()
        sys.exit(1)

    # --- Section 2: collision guard ---
    if not run_collision_guard():
        cache.save()
        sys.exit(1)

    # --- Section 3: precision cases ---
    passed, _ = run_precision_cases(cache, client, precision_prompt)
    if not passed:
        cache.save()
        sys.exit(1)

    # --- Section 4: fallback cases ---
    if not run_fallback_cases(cache, client, fallback_prompt):
        cache.save()
        sys.exit(1)

    total = len(test_cases) + len(PRECISION_CASES) + len(FALLBACK_CASES)
    print(f"\nAll {total} test cases passed. Cache size: {len(cache)} entries.")
    cache.save()


if __name__ == "__main__":
    main()
