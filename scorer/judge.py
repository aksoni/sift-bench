import json
import logging
import time
from typing import Optional

import anthropic

from .judge_cache import (
    JudgeCache,
    JudgeVerdict,
    PrecisionVerdict,
    make_cache_key,
    make_fallback_cache_key,
    make_precision_cache_key,
)

MAX_RETRIES = 5


class JudgeApiError(RuntimeError):
    pass


class JudgeParseError(RuntimeError):
    pass


def judge_pair(
    gt_finding: dict,
    agent_finding: dict,
    *,
    cache: JudgeCache,
    client: anthropic.Anthropic,
    model_snapshot: str,
    prompt_template: str,
) -> JudgeVerdict:
    gt_id = gt_finding.get("id", "")
    agent_id = agent_finding.get("id", "")

    cache_key = make_cache_key(gt_finding, agent_finding, model_snapshot, prompt_template)
    if cache_key in cache:
        return cache.get(cache_key)

    gt_evidence = json.dumps(gt_finding.get("evidence", {}), indent=2)
    agent_evidence = json.dumps(agent_finding.get("evidence", {}), indent=2)

    rendered = prompt_template.format(
        gt_id=gt_id,
        gt_title=gt_finding.get("title", ""),
        gt_description=gt_finding.get("description", ""),
        gt_evidence=gt_evidence,
        agent_id=agent_id,
        agent_title=agent_finding.get("title", ""),
        agent_description=agent_finding.get("description", ""),
        agent_evidence=agent_evidence,
    )

    verdict = _call_judge(rendered, gt_id, agent_id, client, model_snapshot, _parse_match_verdict)
    cache.put(
        cache_key,
        verdict,
        meta={"gt_id": gt_id, "agent_id": agent_id, "model_snapshot": model_snapshot},
    )
    return verdict


def judge_fallback_pair(
    gt_finding: dict,
    agent_finding: dict,
    *,
    cache: JudgeCache,
    client: anthropic.Anthropic,
    model_snapshot: str,
    fallback_prompt_template: str,
) -> JudgeVerdict:
    gt_id = gt_finding.get("id", "")
    agent_id = agent_finding.get("id", "")

    cache_key = make_fallback_cache_key(gt_finding, agent_finding, model_snapshot, fallback_prompt_template)
    if cache_key in cache:
        return cache.get(cache_key)

    gt_evidence = json.dumps(gt_finding.get("evidence", {}), indent=2)
    agent_evidence = json.dumps(agent_finding.get("evidence", {}), indent=2)

    rendered = fallback_prompt_template.format(
        gt_id=gt_id,
        gt_title=gt_finding.get("title", ""),
        gt_description=gt_finding.get("description", ""),
        gt_evidence=gt_evidence,
        agent_id=agent_id,
        agent_title=agent_finding.get("title", ""),
        agent_description=agent_finding.get("description", ""),
        agent_evidence=agent_evidence,
    )

    verdict = _call_judge(rendered, gt_id, agent_id, client, model_snapshot, _parse_match_verdict)
    cache.put(
        cache_key,
        verdict,
        meta={"gt_id": gt_id, "agent_id": agent_id, "model_snapshot": model_snapshot, "via_fallback": True},
    )
    return verdict


def judge_precision(
    agent_finding: dict,
    *,
    cache: JudgeCache,
    client: anthropic.Anthropic,
    model_snapshot: str,
    precision_prompt_template: str,
) -> PrecisionVerdict:
    agent_id = agent_finding.get("id", "")

    cache_key = make_precision_cache_key(agent_finding, model_snapshot, precision_prompt_template)
    if cache_key in cache:
        return cache.get_precision(cache_key)

    agent_evidence = json.dumps(agent_finding.get("evidence", {}), indent=2)

    rendered = precision_prompt_template.format(
        agent_id=agent_id,
        agent_title=agent_finding.get("title", ""),
        agent_description=agent_finding.get("description", ""),
        agent_evidence=agent_evidence,
    )

    verdict = _call_judge(rendered, "precision", agent_id, client, model_snapshot, _parse_precision_verdict)
    cache.put_precision(
        cache_key,
        verdict,
        meta={"agent_id": agent_id, "model_snapshot": model_snapshot},
    )
    return verdict


# --- internal helpers ---

def _call_judge(rendered: str, label_a: str, label_b: str, client, model_snapshot: str, parser):
    delay = 1
    for attempt in range(MAX_RETRIES):
        try:
            response = client.messages.create(
                model=model_snapshot,
                max_tokens=512,
                temperature=0,
                messages=[{"role": "user", "content": rendered}],
            )
            text = "".join(
                block.text for block in response.content if hasattr(block, "text")
            ).strip()

            if text.startswith("```"):
                lines = text.splitlines()
                start = 1
                end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
                text = "\n".join(lines[start:end]).strip()

            return parser(text, label_a, label_b)

        except (anthropic.APIError, anthropic.APIConnectionError):
            if attempt < MAX_RETRIES - 1:
                time.sleep(delay)
                delay *= 2

    raise JudgeApiError(
        f"Judge API failed after {MAX_RETRIES} attempts for {label_a}/{label_b}"
    )


def _parse_match_verdict(text: str, label_a: str, label_b: str) -> JudgeVerdict:
    try:
        obj = json.loads(text)
        return JudgeVerdict(
            match=bool(obj["match"]),
            confidence=int(obj["confidence"]),
            reasoning=str(obj["reasoning"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise JudgeParseError(
            f"Judge returned unparseable response for {label_a}/{label_b}: {e}"
        ) from e


def _parse_precision_verdict(text: str, label_a: str, label_b: str) -> PrecisionVerdict:
    try:
        obj = json.loads(text)
        return PrecisionVerdict(
            legitimate=bool(obj["legitimate"]),
            confidence=int(obj["confidence"]),
            reasoning=str(obj["reasoning"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise JudgeParseError(
            f"Judge returned unparseable precision response for {label_b}: {e}"
        ) from e
