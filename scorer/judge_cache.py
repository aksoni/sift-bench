import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class JudgeVerdict:
    match: bool
    confidence: int
    reasoning: str


def make_cache_key(gt_id: str, agent_id: str, model_snapshot_id: str, prompt_template: str) -> str:
    prompt_hash = hashlib.sha256(prompt_template.encode()).hexdigest()
    raw = f"{gt_id}|{agent_id}|{model_snapshot_id}|{prompt_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


class JudgeCache:
    def __init__(self, path: "str | Path" = "scorer_cache/judge_verdicts.json"):
        self._path = Path(path)
        self._store: dict = {}
        if self._path.exists() and self._path.stat().st_size > 0:
            self._store = json.loads(self._path.read_text())

    def get(self, cache_key: str) -> Optional[JudgeVerdict]:
        entry = self._store.get(cache_key)
        if entry is None:
            return None
        return JudgeVerdict(
            match=entry["match"],
            confidence=entry["confidence"],
            reasoning=entry["reasoning"],
        )

    def put(self, cache_key: str, verdict: JudgeVerdict, meta: Optional[dict] = None) -> None:
        self._store[cache_key] = {
            "match": verdict.match,
            "confidence": verdict.confidence,
            "reasoning": verdict.reasoning,
        }
        if meta:
            self._store[cache_key]["_meta"] = meta

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._store, sort_keys=True, indent=2))

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, cache_key: str) -> bool:
        return cache_key in self._store
