"""Tests for semantic_analysis.detectors.shadowing — _text, _mk_name_finding, _mk_desc_finding."""
from __future__ import annotations

from uuid import uuid4

from mcp_threat_analysis.semantic_analysis.detectors.shadowing import (
    _mk_desc_finding,
    _mk_name_finding,
    _text,
)
from mcp_threat_analysis.semantic_analysis.models import (
    SemanticAnalysisContext,
    ToolSnapshot,
)


def _ts(name: str = "read_file", description: str = "reads a file") -> ToolSnapshot:
    return ToolSnapshot(
        tool_id=uuid4(),
        server_id=uuid4(),
        name=name,
        description=description,
        input_schema={"type": "object"},
        annotations={},
        handler=None,
    )


def _ctx() -> SemanticAnalysisContext:
    return SemanticAnalysisContext(
        server_id=uuid4(), version="1", artifact_ref="test:1",
    )


# --- _text tests ---

def test_text_combines_name_and_description():
    t = _ts(name="read_file", description="reads a file")
    assert _text(t) == "read_file\nreads a file"


def test_text_strips_whitespace():
    t = _ts(name="read_file", description="  ")
    assert _text(t).strip() == "read_file"


# --- _mk_name_finding tests ---

def test_mk_name_finding_same_name_high_severity():
    ctx = _ctx()
    tool = _ts(name="read_file")
    hit = {"id": str(uuid4()), "server_id": str(uuid4()), "name": "read_file"}
    f = _mk_name_finding(ctx, tool, hit)
    assert f.detector == "shadow:name-collision"
    assert f.severity == "high"
    assert f.confidence == 0.85
    assert f.evidence["tool_name"] == "read_file"


def test_mk_name_finding_different_name_medium_severity():
    ctx = _ctx()
    tool = _ts(name="read_file")
    hit = {"id": str(uuid4()), "server_id": str(uuid4()), "name": "get_file"}
    f = _mk_name_finding(ctx, tool, hit)
    # "get_file" != "read_file" even case-insensitively
    assert f.severity == "medium"
    assert f.confidence == 0.7


def test_mk_name_finding_evidence_key():
    ctx = _ctx()
    tool = _ts(name="read_file")
    sid = str(uuid4())
    hit = {"id": str(uuid4()), "server_id": sid, "name": "read_file"}
    f = _mk_name_finding(ctx, tool, hit)
    assert "shadow:name:" in f.evidence["evidence_key"]
    assert sid in f.evidence["evidence_key"]


# --- _mk_desc_finding tests ---

def test_mk_desc_finding():
    ctx = _ctx()
    tool = _ts(name="read_file")
    hit = {"id": str(uuid4()), "server_id": str(uuid4()), "name": "other", "sim": 0.95}
    f = _mk_desc_finding(ctx, tool, hit)
    assert f.detector == "shadow:semantic-clone"
    assert f.severity == "medium"
    assert f.confidence == 0.95
    assert f.evidence["similarity"] == 0.95


def test_mk_desc_finding_default_similarity():
    ctx = _ctx()
    tool = _ts()
    hit = {"id": str(uuid4()), "server_id": str(uuid4()), "name": "other"}
    f = _mk_desc_finding(ctx, tool, hit)
    assert f.confidence == 0.93  # default when sim missing
