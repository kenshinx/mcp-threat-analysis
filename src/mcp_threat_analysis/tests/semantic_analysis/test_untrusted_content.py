"""Tests for semantic_analysis.detectors.untrusted_content — regex, _dump, detector logic."""
from __future__ import annotations

import asyncio

import pytest
from uuid import uuid4

from mcp_threat_analysis.common.models import ToolHandler
from mcp_threat_analysis.semantic_analysis.detectors.untrusted_content import (
    UntrustedContentDetector,
    _UNTRUSTED_MARKER,
    _UNTRUSTED_VERBS,
    _dump,
)
from mcp_threat_analysis.semantic_analysis.models import (
    SemanticAnalysisContext,
    ToolSnapshot,
)


def _ctx(tools: list[ToolSnapshot]) -> SemanticAnalysisContext:
    return SemanticAnalysisContext(
        server_id=uuid4(), version="1", artifact_ref="test:1", tools=tools,
    )


def _tool(
    name: str = "fetch_url",
    description: str = "fetches a url",
    string_literals: list[str] | None = None,
) -> ToolSnapshot:
    handler = ToolHandler(
        name=name,
        declared_description=description,
        declared_input_schema={"type": "object"},
        file="f.py",
        line_start=1,
        line_end=10,
        string_literals=string_literals or [],
    )
    return ToolSnapshot(
        tool_id=uuid4(),
        server_id=uuid4(),
        name=name,
        description=description,
        input_schema={"type": "object"},
        annotations={},
        handler=handler,
    )


# --- regex tests ---

def test_untrusted_verbs_match():
    assert _UNTRUSTED_VERBS.search("fetch the data")
    assert _UNTRUSTED_VERBS.search("Search the web")
    assert _UNTRUSTED_VERBS.search("browse a page")


def test_untrusted_verbs_no_match():
    assert not _UNTRUSTED_VERBS.search("compute sum")
    assert not _UNTRUSTED_VERBS.search("read file")


def test_untrusted_marker_match():
    assert _UNTRUSTED_MARKER.search("returns untrusted content")
    assert _UNTRUSTED_MARKER.search("external_content")
    assert _UNTRUSTED_MARKER.search("external content")


def test_untrusted_marker_no_match():
    assert not _UNTRUSTED_MARKER.search("returns processed data")


# --- _dump tests ---

def test_dump_none():
    assert _dump(None) == ""


def test_dump_str():
    assert _dump("hello") == "hello"


def test_dump_dict():
    result = _dump({"a": 1})
    assert '"a"' in result


def test_dump_unserializable():
    result = _dump(object())
    assert isinstance(result, str)


# --- detector tests ---

@pytest.mark.asyncio
async def test_fires_on_untrusted_verb_without_marker():
    det = UntrustedContentDetector()
    ctx = _ctx([_tool(name="fetch_url", description="fetch a web page")])
    findings = await det.run(session=None, ctx=ctx)
    assert len(findings) == 1
    assert findings[0].detector == "untrusted-content:unmarked"
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_suppressed_by_marker():
    det = UntrustedContentDetector()
    ctx = _ctx([_tool(name="fetch_url", description="fetch untrusted content")])
    findings = await det.run(session=None, ctx=ctx)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_suppressed_by_sanitizer():
    det = UntrustedContentDetector()
    ctx = _ctx([_tool(
        name="fetch_url",
        description="fetch a page",
        string_literals=["html.escape(result)"],
    )])
    findings = await det.run(session=None, ctx=ctx)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_no_finding_for_non_fetch_tool():
    det = UntrustedContentDetector()
    ctx = _ctx([_tool(name="add_numbers", description="adds two numbers")])
    findings = await det.run(session=None, ctx=ctx)
    assert len(findings) == 0
