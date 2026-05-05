"""auth-missing detector.

If the probe completed against a non-loopback endpoint with no Authorization /
API-key header, and the server returned a non-empty tools list, flag it: the
description surface — which is itself prompt-injection territory — is exposed
to the open internet.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import ProbeResult, RemoteFinding

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def detect_auth_missing(result: ProbeResult) -> list[RemoteFinding]:
    if not result.ok or result.auth_kind != "none":
        return []
    host = (urlparse(result.request.endpoint).hostname or "").lower()
    if host in _LOOPBACK or host.endswith(".local"):
        return []
    if not result.tools:
        return []
    return [RemoteFinding(
        detector="remote:auth-missing",
        severity="medium",
        confidence=0.9,
        evidence={
            "endpoint": result.request.endpoint,
            "host": host,
            "tools_count": len(result.tools),
            "evidence_key": f"auth-missing:{result.request.endpoint}",
            "rationale":
                "tools/list returned without any Authorization or API-key header — "
                "the tool description surface (a prompt-injection vector) is "
                "reachable by anyone on the internet.",
        },
        issue_code="R003",
    )]
