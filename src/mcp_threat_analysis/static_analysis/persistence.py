"""static_analysis: persistence: findings + static_summary."""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.models import StaticSummary, ToolHandler
from ..common.persistence import upsert_findings as _upsert
from .models import StaticAnalysisResult


def _serialize_handler(h: ToolHandler) -> dict[str, Any]:
    d = asdict(h)
    return d


async def save_static_findings(
    session: AsyncSession,
    server_id: UUID,
    version: str,
    artifact_ref: str,
    result: StaticAnalysisResult,
) -> list[UUID]:
    summary = StaticSummary(
        server_id=server_id,
        version=version,
        tool_handlers=result.context.tool_handlers,
        string_literals=result.context.string_bag.literals,
        declared_egress_domains=result.context.declared_egress_domains,
        obfuscation_score=result.context.obfuscation_score,
        manifest_facts=result.context.manifest_facts,
        sca_dep_list=[],
    )
    payload = {
        "tool_handlers": [_serialize_handler(h) for h in summary.tool_handlers],
        "string_literals": summary.string_literals[:5000],
        "hosts": list(result.context.string_bag.hosts)[:1000],
        "declared_egress_domains": summary.declared_egress_domains,
        "obfuscation_score": summary.obfuscation_score,
        "manifest_facts": summary.manifest_facts,
        "sca_deps": result.context.sca_deps,
    }
    await session.execute(
        text(
            """
            INSERT INTO static_summaries (server_id, version, summary, written_at)
            VALUES (:sid, :ver, CAST(:s AS JSONB), now())
            ON CONFLICT (server_id, version)
            DO UPDATE SET summary = EXCLUDED.summary, written_at = now()
            """
        ),
        {"sid": str(server_id), "ver": version, "s": json.dumps(payload, default=str)},
    )
    return await _upsert(session, server_id, artifact_ref, result.findings)
