"""Cross-detector consistency boost rules."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(slots=True)
class BoostRule:
    name: str
    require: list[Callable[[dict], bool]]
    boost: float


def detector_eq(name: str) -> Callable[[dict], bool]:
    return lambda f: f["detector"] == name


def detector_match(pattern: str) -> Callable[[dict], bool]:
    rx = re.compile(pattern)
    return lambda f: bool(rx.match(f["detector"]))


DEFAULT_RULES: list[BoostRule] = [
    BoostRule(
        name="schema_code_corroborates_egress",
        require=[
            detector_eq("llm:schema-code-inconsistency"),
            detector_eq("dynamic-egress:undeclared-domain"),
        ],
        boost=0.3,
    ),
    BoostRule(
        name="postmark-style",
        require=[
            detector_match(r"version-diff:.*bcc.*"),
            detector_eq("dynamic-egress:undeclared-domain"),
        ],
        boost=0.5,
    ),
    BoostRule(
        name="text-rule-corroborates-llm",
        require=[
            detector_match(r"tpa-rule:tool-poisoning-.*"),
            detector_eq("tpa-llm"),
        ],
        boost=0.2,
    ),
]


class CrossValidator:
    def __init__(self, rules: list[BoostRule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES

    def total_boost(self, findings: list[dict]) -> tuple[float, list[str]]:
        triggered: list[str] = []
        boost = 0.0
        for rule in self.rules:
            if all(any(pred(f) for f in findings) for pred in rule.require):
                boost += rule.boost
                triggered.append(rule.name)
        return boost, triggered
