"""Tests for semantic_analysis.llm.cache — sha, LLMCache, to_json."""
from __future__ import annotations

from mcp_threat_analysis.semantic_analysis.llm.cache import LLMCache, sha


def test_sha_deterministic():
    assert sha("hello") == sha("hello")
    assert sha("a") != sha("b")


def test_sha_length():
    assert len(sha("x")) == 64  # SHA-256 hex digest


def test_cache_miss():
    c = LLMCache()
    assert c.get("det", "model", "prompt", "payload") is None


def test_cache_put_get():
    c = LLMCache()
    c.put("det", "model", "prompt", "payload", {"result": True})
    assert c.get("det", "model", "prompt", "payload") == {"result": True}


def test_cache_different_prompt_is_miss():
    c = LLMCache()
    c.put("det", "model", "prompt_a", "payload", 1)
    assert c.get("det", "model", "prompt_b", "payload") is None


def test_cache_different_model_is_miss():
    c = LLMCache()
    c.put("det", "model_a", "prompt", "payload", 1)
    assert c.get("det", "model_b", "prompt", "payload") is None


def test_cache_overwrite():
    c = LLMCache()
    c.put("d", "m", "p", "x", "old")
    c.put("d", "m", "p", "x", "new")
    assert c.get("d", "m", "p", "x") == "new"


def test_to_json_deterministic_keys():
    result = LLMCache.to_json({"b": 1, "a": 2})
    assert result == '{"a": 2, "b": 1}'


def test_to_json_handles_datetime():
    from datetime import datetime
    dt = datetime(2025, 1, 1, 12, 0)
    result = LLMCache.to_json({"ts": dt})
    assert "2025" in result
