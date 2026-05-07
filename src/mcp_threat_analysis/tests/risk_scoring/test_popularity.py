"""Tests for risk_scoring.popularity — static factor() method."""
from __future__ import annotations

from mcp_threat_analysis.risk_scoring.popularity import PopularityProvider


def test_factor_zero():
    assert PopularityProvider.factor(0.0) == 1.0


def test_factor_half():
    assert PopularityProvider.factor(0.5) == 1.5


def test_factor_one():
    assert PopularityProvider.factor(1.0) == 2.0


def test_factor_clamps_negative():
    assert PopularityProvider.factor(-0.5) == 1.0


def test_factor_clamps_above_one():
    assert PopularityProvider.factor(1.5) == 2.0
