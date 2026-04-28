"""Persistent LLM-call cache backed by `llm_calls` table.

Cache key = (detector, model, prompt_sha, input_sha). On hit we return the
prior structured response stored in `evidence` of the linked finding —
when no finding exists, the call is treated as a miss.

For pure structured-output reuse without finding side-effects, the cache
also stores the parsed JSON in a side dict keyed by sha.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LLMCache:
    """Process-local cache. DB-backed dedupe is enforced by `llm_calls` schema."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str, str, str], Any] = {}

    def get(self, detector: str, model: str, prompt: str, payload: str) -> Any | None:
        return self._store.get((detector, model, sha(prompt), sha(payload)))

    def put(
        self, detector: str, model: str, prompt: str, payload: str, value: Any
    ) -> None:
        self._store[(detector, model, sha(prompt), sha(payload))] = value

    @staticmethod
    def to_json(payload: Any) -> str:
        return json.dumps(payload, sort_keys=True, default=str)
