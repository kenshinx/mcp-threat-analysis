"""remote_analysis: write paths.

Three things happen on a successful probe:

1. Insert a `remote_observations` row capturing the raw probe.
2. Synthesize / upsert a `tools` row per tool reported by the server, so the
   existing semantic_analysis layer (`shadow:*`, `char:hidden-unicode`, `tpa-llm`,
   `untrusted-content:unmarked`) can run unchanged on remote-only servers.
3. Write a minimal `static_summaries` row marked `kind='remote'` so the
   semantic orchestrator's "load static_summary" step doesn't fail.
4. upsert_findings() the remote_analysis-layer findings via the shared helper.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.models import Finding
from ..common.persistence import upsert_findings
from .models import PROBE_VERSION, ProbeResult, RemoteFinding


async def insert_observation(
    session: AsyncSession, *, server_id: UUID, result: ProbeResult
) -> UUID:
    tls = asdict(result.tls) if result.tls else None
    error = result.error
    payload = {
        "sid": str(server_id),
        "pv": PROBE_VERSION,
        "transport": result.request.transport,
        "endpoint": result.request.endpoint,
        "ok": result.ok,
        "proto": result.protocol_ver,
        "server_info": json.dumps(result.server_info) if result.server_info else None,
        "caps": json.dumps(result.capabilities) if result.capabilities else None,
        "tools": json.dumps(result.tools) if result.tools else None,
        "resources": json.dumps(result.resources) if result.resources else None,
        "prompts": json.dumps(result.prompts) if result.prompts else None,
        "tls": json.dumps(tls) if tls else None,
        "auth": result.auth_kind,
        "lat": result.latency_ms,
        "err": json.dumps(error) if error else None,
    }
    row = await session.execute(
        text(
            """
            INSERT INTO remote_observations
              (server_id, probe_version, transport, endpoint, ok, protocol_ver,
               server_info, capabilities, tools, resources, prompts, tls,
               auth_kind, latency_ms, error)
            VALUES
              (:sid, :pv, :transport, :endpoint, :ok, :proto,
               CAST(:server_info AS JSONB), CAST(:caps AS JSONB),
               CAST(:tools AS JSONB), CAST(:resources AS JSONB),
               CAST(:prompts AS JSONB), CAST(:tls AS JSONB),
               :auth, :lat, CAST(:err AS JSONB))
            RETURNING id
            """
        ),
        payload,
    )
    return row.scalar_one()


async def sync_tools(
    session: AsyncSession, *, server_id: UUID, snapshot_ref: str, tools: list[dict[str, Any]]
) -> int:
    """Upsert one `tools` row per probe-reported tool, keyed by (server_id, name)."""
    n = 0
    for t in tools:
        name = t.get("name")
        if not name:
            continue
        await session.execute(
            text(
                """
                INSERT INTO tools (server_id, snapshot_ref, name, description,
                                   input_schema, annotations)
                VALUES (:sid, :sr, :name, :desc,
                        CAST(:schema AS JSONB), CAST(:ann AS JSONB))
                ON CONFLICT DO NOTHING
                """
            ),
            {
                "sid": str(server_id),
                "sr": snapshot_ref,
                "name": name,
                "desc": t.get("description") or "",
                "schema": json.dumps(t.get("inputSchema") or {}),
                "ann": json.dumps(t.get("annotations") or {}),
            },
        )
        n += 1
    return n


async def write_remote_summary(
    session: AsyncSession, *, server_id: UUID, version: str, result: ProbeResult
) -> None:
    """Write a stub static_summary so semantic_analysis won't fail to load one.

    The summary's shape mirrors `StaticSummary` but with empty handler / IO
    arrays — remote servers have no source-code-level data. The `kind: 'remote'`
    marker is what signals this distinction to consumers.
    """
    summary = {
        "kind": "remote",
        "transport": result.request.transport,
        "endpoint": result.request.endpoint,
        "protocol_ver": result.protocol_ver,
        "server_info": result.server_info,
        "tool_handlers": [],
        "string_literals": [],
        "manifest_facts": {},
        "declared_egress_domains": [],
        "sca_deps": [],
        "obfuscation_score": 0.0,
        "languages": [],
    }
    await session.execute(
        text(
            """
            INSERT INTO static_summaries (server_id, version, summary)
            VALUES (:sid, :ver, CAST(:summary AS JSONB))
            ON CONFLICT (server_id, version) DO UPDATE
              SET summary = EXCLUDED.summary, written_at = now()
            """
        ),
        {"sid": str(server_id), "ver": version, "summary": json.dumps(summary)},
    )


async def write_findings(
    session: AsyncSession,
    *,
    server_id: UUID,
    artifact_ref: str,
    observation_id: UUID,
    findings: list[RemoteFinding],
) -> list[UUID]:
    """Convert RemoteFinding records to common.Finding and upsert them."""
    payloads = []
    for rf in findings:
        ev = dict(rf.evidence)
        ev.setdefault("observation_id", str(observation_id))
        payloads.append(Finding(
            detector=rf.detector,
            layer="remote_analysis",
            severity=rf.severity,
            confidence=rf.confidence,
            evidence=ev,
            artifact_ref=artifact_ref,
            issue_code=rf.issue_code,
        ))
    return await upsert_findings(session, server_id, artifact_ref, payloads)
