"""Tests for semantic_analysis.detectors.toxic_flow — pattern structure, CAPABILITY_VOCAB."""
from __future__ import annotations

from mcp_threat_analysis.semantic_analysis.detectors.toxic_flow import (
    CAPABILITY_VOCAB,
    TOXIC_FLOW_PATTERNS,
)


def test_patterns_have_required_keys():
    for p in TOXIC_FLOW_PATTERNS:
        assert "name" in p
        assert "sources" in p
        assert "sinks" in p
        assert "severity" in p


def test_patterns_sources_and_sinks_are_lists():
    for p in TOXIC_FLOW_PATTERNS:
        assert isinstance(p["sources"], list)
        assert isinstance(p["sinks"], list)
        assert len(p["sources"]) > 0
        assert len(p["sinks"]) > 0


def test_patterns_severity_valid():
    valid = {"low", "medium", "high", "critical"}
    for p in TOXIC_FLOW_PATTERNS:
        assert p["severity"] in valid


def test_patterns_names_unique():
    names = [p["name"] for p in TOXIC_FLOW_PATTERNS]
    assert len(names) == len(set(names))


def test_vocab_contains_all_source_and_sink_capabilities():
    all_caps = set()
    for p in TOXIC_FLOW_PATTERNS:
        all_caps.update(p["sources"])
        all_caps.update(p["sinks"])
    assert all_caps.issubset(set(CAPABILITY_VOCAB))


def test_vocab_is_sorted():
    assert CAPABILITY_VOCAB == sorted(CAPABILITY_VOCAB)


def test_at_least_two_patterns():
    assert len(TOXIC_FLOW_PATTERNS) >= 2


def test_untrusted_read_to_sensitive_write_exists():
    names = {p["name"] for p in TOXIC_FLOW_PATTERNS}
    assert "untrusted-read-to-sensitive-write" in names
