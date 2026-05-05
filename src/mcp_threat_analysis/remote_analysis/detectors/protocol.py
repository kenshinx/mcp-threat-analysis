"""protocol-version-mismatch detector."""
from __future__ import annotations

from ..models import ProbeResult, RemoteFinding
from ..transport.streamable_http import KNOWN_PROTOCOL_VERSIONS


def detect_protocol_version(result: ProbeResult) -> list[RemoteFinding]:
    if not result.ok or not result.protocol_ver:
        return []
    if result.protocol_ver in KNOWN_PROTOCOL_VERSIONS:
        return []
    return [RemoteFinding(
        detector="remote:protocol-version-mismatch",
        severity="info",
        confidence=0.85,
        evidence={
            "endpoint": result.request.endpoint,
            "reported": result.protocol_ver,
            "known": sorted(KNOWN_PROTOCOL_VERSIONS),
            "evidence_key": f"proto-ver:{result.request.endpoint}:{result.protocol_ver}",
            "rationale":
                "server reported a protocolVersion outside the set we recognize; "
                "may be a typo, a pre-release build, or a fork — worth a glance.",
        },
        issue_code="R004",
    )]
