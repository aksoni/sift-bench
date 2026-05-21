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


@dataclass
class PrecisionVerdict:
    legitimate: bool
    confidence: int
    reasoning: str


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _content_hash(finding: dict) -> str:
    return _sha256(json.dumps(finding, sort_keys=True))


def make_cache_key(gt_finding: dict, agent_finding: dict, model_snapshot_id: str, prompt_template: str) -> str:
    # Content-addressed: hashes finding content, not IDs, to prevent cross-run stale verdict collisions
    raw = f"match_v0.5|{_content_hash(gt_finding)}|{_content_hash(agent_finding)}|{model_snapshot_id}|{_sha256(prompt_template)}"
    return _sha256(raw)


def make_precision_cache_key(agent_finding: dict, model_snapshot_id: str, prompt_template: str) -> str:
    raw = f"precision_v0.5|{_content_hash(agent_finding)}|{model_snapshot_id}|{_sha256(prompt_template)}"
    return _sha256(raw)


def make_fallback_cache_key(gt_finding: dict, agent_finding: dict, model_snapshot_id: str, prompt_template: str) -> str:
    raw = f"fallback_v0.5|{_content_hash(gt_finding)}|{_content_hash(agent_finding)}|{model_snapshot_id}|{_sha256(prompt_template)}"
    return _sha256(raw)


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

    def get_precision(self, cache_key: str) -> Optional[PrecisionVerdict]:
        entry = self._store.get(cache_key)
        if entry is None:
            return None
        return PrecisionVerdict(
            legitimate=entry["legitimate"],
            confidence=entry["confidence"],
            reasoning=entry["reasoning"],
        )

    def put_precision(self, cache_key: str, verdict: PrecisionVerdict, meta: Optional[dict] = None) -> None:
        self._store[cache_key] = {
            "legitimate": verdict.legitimate,
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
