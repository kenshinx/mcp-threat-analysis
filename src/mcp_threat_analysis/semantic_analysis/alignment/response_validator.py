"""Validates alignment LLM responses against the unified schema."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class InvalidAlignmentResponse(Exception):
    pass


@dataclass(slots=True)
class AlignmentVerdict:
    alignment_score: int  # 0..10
    aligned: bool
    behavioral_diff: list[dict[str, Any]]
    explanation: str
    confidence: float


def validate(parsed: dict[str, Any]) -> AlignmentVerdict:
    if not isinstance(parsed, dict):
        raise InvalidAlignmentResponse("expected JSON object")
    score = parsed.get("alignment_score")
    if not isinstance(score, (int, float)) or not 0 <= score <= 10:
        raise InvalidAlignmentResponse("alignment_score missing or out of range")
    aligned = bool(parsed.get("aligned", score > 6))
    diff = parsed.get("behavioral_diff") or []
    if not isinstance(diff, list):
        raise InvalidAlignmentResponse("behavioral_diff must be a list")
    confidence = float(parsed.get("confidence", 0.7))
    explanation = str(parsed.get("explanation", ""))[:5000]
    return AlignmentVerdict(
        alignment_score=int(score),
        aligned=aligned,
        behavioral_diff=diff,
        explanation=explanation,
        confidence=max(0.0, min(1.0, confidence)),
    )
