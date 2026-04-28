"""Server-level risk aggregator.

Score formula (linear, by design):
    score = sum_over_active_findings( SEV[f.severity]
                                     * CLASS[detector_class(f.detector)]
                                     * f.confidence )
    score *= (1 + cross_validation_boost)
    score *= (1 + popularity)
    score = min(100, score)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.logging import get_logger
from .cross_validator import CrossValidator
from .popularity import PopularityProvider
from .weights import Weights, load_weights

log = get_logger(__name__)


@dataclass(slots=True)
class AggregateResult:
    server_id: UUID
    score: float
    base_score: float
    boost: float
    boost_rules: list[str]
    popularity: float
    finding_count: int
    weights_version: str
    top_findings: list[dict[str, Any]]


class Aggregator:
    def __init__(
        self,
        weights: Weights | None = None,
        cross_validator: CrossValidator | None = None,
        popularity: PopularityProvider | None = None,
    ) -> None:
        self.weights = weights or load_weights()
        self.cv = cross_validator or CrossValidator()
        self.popularity = popularity or PopularityProvider()

    async def aggregate(
        self,
        session: AsyncSession,
        server_id: UUID,
        *,
        write_history: bool = True,
    ) -> AggregateResult:
        rows = await session.execute(
            text(
                """
                SELECT id, detector, layer, severity, confidence, evidence
                  FROM findings
                 WHERE server_id = :sid AND status = 'active'
                """
            ),
            {"sid": str(server_id)},
        )
        findings = [dict(r._mapping) for r in rows.all()]

        base = 0.0
        for f in findings:
            sw = self.weights.severity.get(f["severity"], 0.0)
            cw = self.weights.class_weight(f["detector"])
            base += sw * cw * float(f["confidence"] or 0.0)

        boost, triggered = self.cv.total_boost(findings)
        pop = await self.popularity.get(session, server_id)
        score = base * (1.0 + boost) * (1.0 + pop)
        score = min(100.0, score)

        top = sorted(
            findings,
            key=lambda f: self.weights.severity.get(f["severity"], 0.0)
            * self.weights.class_weight(f["detector"])
            * float(f["confidence"] or 0.0),
            reverse=True,
        )[:5]
        digest = [
            {
                "id": str(f["id"]),
                "detector": f["detector"],
                "severity": f["severity"],
                "confidence": float(f["confidence"] or 0.0),
            }
            for f in top
        ]

        priority = _priority(score, findings)
        await session.execute(
            text(
                """
                UPDATE servers
                   SET risk_score = :score,
                       risk_priority = :prio,
                       risk_updated_at = now(),
                       weights_version = :wv
                 WHERE id = :sid
                """
            ),
            {
                "score": score,
                "prio": priority,
                "wv": self.weights.version,
                "sid": str(server_id),
            },
        )
        if write_history:
            await session.execute(
                text(
                    """
                    INSERT INTO server_risk_history
                      (server_id, scored_at, score, priority, finding_count,
                       findings_digest, weights_version)
                    VALUES (:sid, now(), :score, :prio, :cnt,
                            CAST(:dig AS JSONB), :wv)
                    """
                ),
                {
                    "sid": str(server_id),
                    "score": score,
                    "prio": priority,
                    "cnt": len(findings),
                    "dig": json.dumps(digest),
                    "wv": self.weights.version,
                },
            )
        return AggregateResult(
            server_id=server_id,
            score=score,
            base_score=base,
            boost=boost,
            boost_rules=triggered,
            popularity=pop,
            finding_count=len(findings),
            weights_version=self.weights.version,
            top_findings=digest,
        )


def _priority(score: float, findings: list[dict]) -> str:
    has_critical_high_conf = any(
        f["severity"] == "critical" and float(f["confidence"] or 0.0) >= 0.9
        for f in findings
    )
    distinct_detectors = len({f["detector"] for f in findings})
    has_high = any(f["severity"] == "high" for f in findings)
    has_medium = any(f["severity"] == "medium" for f in findings)
    if has_critical_high_conf:
        return "P0"
    if distinct_detectors >= 3 and has_high:
        return "P0"
    if has_high:
        return "P1"
    if has_medium:
        return "P2"
    return "P3"
