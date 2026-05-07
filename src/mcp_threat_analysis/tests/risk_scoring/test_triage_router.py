"""Tests for risk_scoring.triage_router — pure function _agg_priority()."""
from __future__ import annotations

from uuid import uuid4

from mcp_threat_analysis.risk_scoring.aggregator import AggregateResult
from mcp_threat_analysis.risk_scoring.triage_router import _agg_priority


def _agg(
    score: float = 50.0,
    top_findings: list[dict] | None = None,
) -> AggregateResult:
    return AggregateResult(
        server_id=uuid4(),
        score=score,
        base_score=score,
        boost=0.0,
        boost_rules=[],
        popularity=0.0,
        finding_count=len(top_findings) if top_findings else 0,
        weights_version="test",
        top_findings=top_findings or [],
    )


def _tf(severity: str, detector: str = "x", confidence: float = 0.9) -> dict:
    return {"id": "1", "severity": severity, "detector": detector, "confidence": confidence}


def test_p0_critical_high_conf():
    agg = _agg(top_findings=[_tf("critical")])
    assert _agg_priority(agg) == "P0"


def test_p0_three_detectors_and_high():
    agg = _agg(top_findings=[_tf("high", "a"), _tf("high", "b"), _tf("high", "c")])
    assert _agg_priority(agg) == "P0"


def test_p1_high_score():
    agg = _agg(score=35.0, top_findings=[_tf("medium")])
    assert _agg_priority(agg) == "P1"


def test_p1_high_severity():
    agg = _agg(top_findings=[_tf("high")])
    assert _agg_priority(agg) == "P1"


def test_p2_medium():
    agg = _agg(score=10.0, top_findings=[_tf("medium")])
    assert _agg_priority(agg) == "P2"


def test_p3_nothing_notable():
    agg = _agg(score=5.0, top_findings=[_tf("low")])
    assert _agg_priority(agg) == "P3"
