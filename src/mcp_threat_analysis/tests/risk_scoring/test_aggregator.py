"""Tests for risk_scoring.aggregator — pure function _priority()."""
from __future__ import annotations

from mcp_threat_analysis.risk_scoring.aggregator import _priority


def _f(severity: str, detector: str = "x", confidence: float = 0.9) -> dict:
    return {"severity": severity, "detector": detector, "confidence": confidence}


def test_p0_critical_high_confidence():
    assert _priority(50.0, [_f("critical")]) == "P0"


def test_p0_not_triggered_when_critical_low_confidence():
    assert _priority(50.0, [_f("critical", confidence=0.5)]) != "P0"


def test_p0_three_distinct_detectors_and_high():
    findings = [_f("high", "a"), _f("high", "b"), _f("high", "c")]
    assert _priority(50.0, findings) == "P0"


def test_p1_single_high():
    assert _priority(30.0, [_f("high")]) == "P1"


def test_p2_medium():
    assert _priority(10.0, [_f("medium")]) == "P2"


def test_p3_low_and_info_only():
    assert _priority(1.0, [_f("low"), _f("info")]) == "P3"


def test_p3_empty():
    assert _priority(0.0, []) == "P3"


def test_p0_critical_takes_precedence_over_high():
    findings = [_f("critical"), _f("high")]
    assert _priority(80.0, findings) == "P0"


def test_two_detectors_not_enough_for_p0():
    findings = [_f("high", "a"), _f("high", "b")]
    assert _priority(30.0, findings) == "P1"


def test_confidence_none_treated_as_zero():
    f = {"severity": "critical", "detector": "x", "confidence": None}
    assert _priority(50.0, [f]) != "P0"
