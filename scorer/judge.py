import json
import logging
import time
from typing import Optional

import anthropic

from .judge_cache import JudgeCache, JudgeVerdict, make_cache_key

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

    cache_key = make_cache_key(gt_id, agent_id, model_snapshot, prompt_template)
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

    verdict: Optional[JudgeVerdict] = None
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

            # Strip markdown fences if model adds them despite instructions
            if text.startswith("```"):
                lines = text.splitlines()
                start = 1
                end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
                text = "\n".join(lines[start:end]).strip()

            obj = json.loads(text)
            verdict = JudgeVerdict(
                match=bool(obj["match"]),
                confidence=int(obj["confidence"]),
                reasoning=str(obj["reasoning"]),
            )
            break
        except (anthropic.APIError, anthropic.APIConnectionError):
            if attempt < MAX_RETRIES - 1:
                time.sleep(delay)
                delay *= 2
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise JudgeParseError(
                f"Judge returned unparseable response for {gt_id}/{agent_id}: {e}"
            ) from e

    if verdict is None:
        raise JudgeApiError(
            f"Judge API failed after {MAX_RETRIES} attempts for {gt_id}/{agent_id}"
        )

    cache.put(
        cache_key,
        verdict,
        meta={"gt_id": gt_id, "agent_id": agent_id, "model_snapshot": model_snapshot},
    )
    return verdict
