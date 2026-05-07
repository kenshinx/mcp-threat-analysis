"""Tests for semantic_analysis.alignment.response_validator."""
from __future__ import annotations

import pytest

from mcp_threat_analysis.semantic_analysis.alignment.response_validator import (
    AlignmentVerdict,
    InvalidAlignmentResponse,
    validate,
)


def test_valid_full_response():
    v = validate({
        "alignment_score": 8,
        "aligned": True,
        "behavioral_diff": [{"desc": "x"}],
        "explanation": "looks good",
        "confidence": 0.9,
    })
    assert isinstance(v, AlignmentVerdict)
    assert v.alignment_score == 8
    assert v.aligned is True
    assert len(v.behavioral_diff) == 1
    assert v.confidence == 0.9


def test_minimal_response():
    v = validate({"alignment_score": 3})
    assert v.alignment_score == 3
    assert v.aligned is False  # score <= 6 → aligned defaults False
    assert v.behavioral_diff == []
    assert v.confidence == 0.7  # default


def test_score_boundaries():
    v0 = validate({"alignment_score": 0})
    assert v0.alignment_score == 0
    v10 = validate({"alignment_score": 10})
    assert v10.alignment_score == 10


def test_invalid_score_too_high():
    with pytest.raises(InvalidAlignmentResponse, match="out of range"):
        validate({"alignment_score": 11})


def test_invalid_score_negative():
    with pytest.raises(InvalidAlignmentResponse, match="out of range"):
        validate({"alignment_score": -1})


def test_missing_score():
    with pytest.raises(InvalidAlignmentResponse, match="missing or out of range"):
        validate({"aligned": True})


def test_non_object_input():
    with pytest.raises(InvalidAlignmentResponse, match="JSON object"):
        validate("not a dict")


def test_behavioral_diff_not_list():
    with pytest.raises(InvalidAlignmentResponse, match="must be a list"):
        validate({"alignment_score": 5, "behavioral_diff": "oops"})


def test_confidence_clamped():
    v = validate({"alignment_score": 5, "confidence": 1.5})
    assert v.confidence == 1.0
    v2 = validate({"alignment_score": 5, "confidence": -0.1})
    assert v2.confidence == 0.0


def test_explanation_truncated():
    v = validate({"alignment_score": 5, "explanation": "x" * 10000})
    assert len(v.explanation) <= 5000


def test_float_score_converted_to_int():
    v = validate({"alignment_score": 7.8})
    assert v.alignment_score == 7
    assert isinstance(v.alignment_score, int)
