"""remote_analysis: probe → detect → persist.

Single entry point used by both the CLI (`mta-remote scan`) and the future
P2 watch daemon. Stateless w.r.t. the registry — caller provides the
ProbeRequest and a canonical_name; this module owns DB writes.
"""
from __future__ import annotations

import structlog

from ..common.db import session_scope
from ..common.persistence import ensure_server
from .detectors import detect_auth_missing, detect_protocol_version, detect_tls
from .models import PROBE_VERSION, ProbeRequest, ProbeResult, ScanOutcome
from .persistence import (
    insert_observation,
    sync_tools,
    write_findings,
    write_remote_summary,
)
from .transport import StreamableHTTPTransport

log = structlog.get_logger(__name__)

_TRANSPORTS = {"streamable_http": StreamableHTTPTransport}


async def scan(req: ProbeRequest, canonical_name: str) -> ScanOutcome:
    """Probe `req.endpoint`, run snapshot detectors, persist everything.

    Returns a ScanOutcome the CLI prints; raises on hard transport
    misconfiguration but never on a remote server's bad behavior — that
    becomes ok=False on the observation row instead.
    """
    transport_cls = _TRANSPORTS.get(req.transport)
    if transport_cls is None:
        raise ValueError(f"unknown transport: {req.transport}")
    transport = transport_cls()
    log.info("probe-start", endpoint=req.endpoint, transport=req.transport)
    result: ProbeResult = await transport.probe(req)
    log.info(
        "probe-done",
        ok=result.ok,
        latency_ms=result.latency_ms,
        tool_count=len(result.tools),
        protocol_ver=result.protocol_ver,
    )

    findings = run_detectors(result)
    artifact_ref = f"remote://{req.transport}/{req.endpoint}"

    async with session_scope() as session:
        server_id = await ensure_server(
            session,
            canonical_name=canonical_name,
            kind="remote",
        )
        observation_id = await insert_observation(
            session, server_id=server_id, result=result
        )
        if result.tools:
            await sync_tools(
                session,
                server_id=server_id,
                snapshot_ref=str(observation_id),
                tools=result.tools,
            )
        await write_remote_summary(
            session,
            server_id=server_id,
            version=PROBE_VERSION,
            result=result,
        )
        await write_findings(
            session,
            server_id=server_id,
            artifact_ref=artifact_ref,
            observation_id=observation_id,
            findings=findings,
        )

    return ScanOutcome(
        server_id=server_id,
        canonical_name=canonical_name,
        observation_id=observation_id,
        result=result,
        findings=findings,
    )


def run_detectors(result: ProbeResult) -> list:
    """Run all P1 snapshot detectors. Pure function — no DB."""
    out = []
    out.extend(detect_tls(result))
    out.extend(detect_auth_missing(result))
    out.extend(detect_protocol_version(result))
    return out
