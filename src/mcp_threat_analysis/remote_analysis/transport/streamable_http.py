"""Streamable-HTTP MCP transport (JSON-RPC 2.0 over POST).

The endpoint accepts POST with a JSON-RPC envelope; the response can be either
JSON (synchronous result) or SSE (server prefers streamed). We `Accept` both
and parse whichever arrives. For initialize + list-style probes the JSON path
is the common case across Anthropic Hosted MCP, Cloudflare Agents, and most
self-hosted streamable-HTTP servers.
"""
from __future__ import annotations

import json
import ssl
import time
from datetime import UTC, datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from ..models import ProbeRequest, ProbeResult, TLSInfo, PROBE_VERSION
from .base import TransportError

log = structlog.get_logger(__name__)

PROTOCOL_VERSION = "2025-03-26"
USER_AGENT = "mta-remote/0.1 (+https://github.com/kenshinx/mcp-threat-analysis)"
KNOWN_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}


class StreamableHTTPTransport:
    name = "streamable_http"

    async def probe(self, req: ProbeRequest) -> ProbeResult:
        started = time.perf_counter()
        probed_at = datetime.now(UTC)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            **req.headers,
        }
        auth_kind = self._classify_auth(req.headers)
        tls_info = await self._collect_tls(req.endpoint)

        # Step 1 — initialize
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mta-remote", "version": "0.1.0"},
            },
        }

        async with httpx.AsyncClient(
            timeout=req.timeout_s,
            follow_redirects=True,
            verify=True,
        ) as client:
            try:
                init_resp = await client.post(req.endpoint, json=init_payload, headers=headers)
            except httpx.HTTPError as e:
                latency = int((time.perf_counter() - started) * 1000)
                return ProbeResult(
                    request=req, ok=False, probed_at=probed_at, latency_ms=latency,
                    tls=tls_info, auth_kind=auth_kind,
                    error={"phase": "initialize", "message": str(e)},
                )

            session_id = init_resp.headers.get("mcp-session-id")
            if session_id:
                headers["mcp-session-id"] = session_id

            init_data = self._parse_jsonrpc_response(init_resp)
            if init_data is None or "result" not in init_data:
                latency = int((time.perf_counter() - started) * 1000)
                return ProbeResult(
                    request=req, ok=False, probed_at=probed_at, latency_ms=latency,
                    tls=tls_info, auth_kind=auth_kind,
                    error={
                        "phase": "initialize",
                        "status": init_resp.status_code,
                        "body": (init_resp.text or "")[:512],
                    },
                )

            init_result = init_data["result"]
            protocol_ver = init_result.get("protocolVersion")
            server_info = init_result.get("serverInfo")
            capabilities = init_result.get("capabilities") or {}

            # Step 2 — fire-and-forget initialized notification
            try:
                await client.post(
                    req.endpoint,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=headers,
                )
            except httpx.HTTPError:
                pass

            # Step 3 — list tools (and opportunistically resources/prompts when advertised)
            tools = await self._list(client, req.endpoint, headers, "tools/list", "tools")
            resources: list[dict[str, Any]] = []
            prompts: list[dict[str, Any]] = []
            if "resources" in capabilities:
                resources = await self._list(
                    client, req.endpoint, headers, "resources/list", "resources"
                )
            if "prompts" in capabilities:
                prompts = await self._list(
                    client, req.endpoint, headers, "prompts/list", "prompts"
                )

        latency = int((time.perf_counter() - started) * 1000)
        return ProbeResult(
            request=req,
            ok=True,
            probed_at=probed_at,
            latency_ms=latency,
            protocol_ver=protocol_ver,
            server_info=server_info,
            capabilities=capabilities,
            tools=tools,
            resources=resources,
            prompts=prompts,
            tls=tls_info,
            auth_kind=auth_kind,
        )

    @staticmethod
    def _classify_auth(headers: dict[str, str]) -> str:
        for k, v in headers.items():
            kl = k.lower()
            if kl == "authorization":
                if v.lower().startswith("bearer "):
                    return "oauth"
                return "header"
            if kl in {"x-api-key", "api-key", "x-auth-token"}:
                return "header"
        return "none"

    @staticmethod
    def _parse_jsonrpc_response(resp: httpx.Response) -> dict[str, Any] | None:
        ctype = resp.headers.get("content-type", "")
        text = resp.text or ""
        if "text/event-stream" in ctype:
            for line in text.splitlines():
                if line.startswith("data:"):
                    payload = line.removeprefix("data:").strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        return json.loads(payload)
                    except json.JSONDecodeError:
                        continue
            return None
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    async def _list(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        headers: dict[str, str],
        method: str,
        result_key: str,
    ) -> list[dict[str, Any]]:
        try:
            resp = await client.post(
                endpoint,
                json={"jsonrpc": "2.0", "id": 100, "method": method, "params": {}},
                headers=headers,
            )
        except httpx.HTTPError as e:
            log.debug("list-failed", method=method, error=str(e))
            return []
        data = self._parse_jsonrpc_response(resp)
        if not data or "result" not in data:
            return []
        out = data["result"].get(result_key) or []
        # Be lenient: some servers wrap in {tools: {tools: [...]}} variants. Trust the spec shape.
        return out if isinstance(out, list) else []

    async def _collect_tls(self, endpoint: str) -> TLSInfo | None:
        url = urlparse(endpoint)
        if url.scheme != "https" or not url.hostname:
            return None
        port = url.port or 443
        # Two passes: once with verification (to learn self_signed = False), once disabled
        # so we still capture the cert when validation fails.
        try:
            cert = await _peek_cert(url.hostname, port, verify=True)
            self_signed = False
        except (ssl.SSLError, OSError):
            try:
                cert = await _peek_cert(url.hostname, port, verify=False)
                self_signed = True
            except (ssl.SSLError, OSError) as e:
                log.debug("tls-collect-failed", host=url.hostname, error=str(e))
                return None
        return _summarize_cert(cert, self_signed=self_signed)


# ---- helpers --------------------------------------------------------------

async def _peek_cert(host: str, port: int, *, verify: bool) -> dict[str, Any]:
    import asyncio

    loop = asyncio.get_running_loop()

    def _do() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with __import__("socket").create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                der = ssock.getpeercert(binary_form=True) or b""
        # sha256 fingerprint
        import hashlib
        cert["_sha256"] = hashlib.sha256(der).hexdigest()
        return cert

    return await loop.run_in_executor(None, _do)


def _summarize_cert(cert: dict[str, Any], *, self_signed: bool) -> TLSInfo:
    def _flatten(rdn_seq: Any) -> str:
        # cert["subject"] = ((('commonName', 'foo'),),) — turn into "CN=foo,O=Bar"
        parts = []
        if not rdn_seq:
            return ""
        for rdn in rdn_seq:
            for kv in rdn:
                parts.append(f"{kv[0]}={kv[1]}")
        return ", ".join(parts)

    not_after_str = cert.get("notAfter")
    not_after_dt = None
    if not_after_str:
        try:
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            not_after_dt = None
    days_left = None
    if not_after_dt:
        days_left = max(0, (not_after_dt - datetime.now(UTC)).days)
    san = []
    for typ, val in cert.get("subjectAltName") or []:
        if typ.lower() == "dns":
            san.append(val)
    return TLSInfo(
        subject=_flatten(cert.get("subject")) or None,
        issuer=_flatten(cert.get("issuer")) or None,
        not_before=cert.get("notBefore"),
        not_after=not_after_str,
        sha256=cert.get("_sha256"),
        self_signed=self_signed,
        days_until_expiry=days_left,
        san=san,
    )
