"""Test the JSON-RPC response parser without hitting the network."""
from __future__ import annotations

import httpx

from mcp_threat_analysis.remote_analysis.transport.streamable_http import (
    StreamableHTTPTransport,
    KNOWN_PROTOCOL_VERSIONS,
)


def _resp(body: str, ctype: str = "application/json", status: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status, content=body.encode(), headers={"content-type": ctype})


def test_parse_plain_json():
    r = _resp('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}')
    out = StreamableHTTPTransport._parse_jsonrpc_response(r)
    assert out and out["result"]["protocolVersion"] == "2025-03-26"


def test_parse_sse_data_lines():
    body = (
        "event: message\n"
        "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n\n"
    )
    r = _resp(body, ctype="text/event-stream")
    out = StreamableHTTPTransport._parse_jsonrpc_response(r)
    assert out and out["result"]["protocolVersion"] == "2025-03-26"


def test_parse_empty_body_returns_none():
    assert StreamableHTTPTransport._parse_jsonrpc_response(_resp("")) is None


def test_parse_invalid_json_returns_none():
    assert StreamableHTTPTransport._parse_jsonrpc_response(_resp("not json")) is None


def test_known_protocol_versions_includes_current():
    assert "2025-03-26" in KNOWN_PROTOCOL_VERSIONS


def test_classify_auth_modes():
    cls = StreamableHTTPTransport._classify_auth
    assert cls({}) == "none"
    assert cls({"Authorization": "Bearer x"}) == "oauth"
    assert cls({"Authorization": "Basic x"}) == "header"
    assert cls({"X-API-Key": "x"}) == "header"
