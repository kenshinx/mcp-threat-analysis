"""semantic_analysis: persistence: load static_summary + tools, write findings."""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.models import Finding, IOSummary, ToolHandler
from ..common.persistence import upsert_findings as _upsert
from .models import ToolSnapshot


async def load_static_summary(
    session: AsyncSession, server_id: UUID, version: str
) -> dict[str, Any] | None:
    row = await session.execute(
        text(
            "SELECT summary FROM static_summaries "
            "WHERE server_id = :sid AND version = :ver"
        ),
        {"sid": str(server_id), "ver": version},
    )
    rec = row.first()
    return rec[0] if rec else None


async def load_tools(
    session: AsyncSession, server_id: UUID
) -> list[ToolSnapshot]:
    rows = await session.execute(
        text(
            """
            SELECT id, server_id, name, description, input_schema, annotations
              FROM tools WHERE server_id = :sid
            """
        ),
        {"sid": str(server_id)},
    )
    out: list[ToolSnapshot] = []
    for r in rows.all():
        m = r._mapping
        out.append(
            ToolSnapshot(
                tool_id=m["id"],
                server_id=m["server_id"],
                name=m["name"] or "",
                description=m["description"] or "",
                input_schema=m["input_schema"] or {},
                annotations=m["annotations"] or {},
                handler=None,
            )
        )
    return out


def hydrate_handlers(
    summary: dict[str, Any] | None,
) -> list[ToolHandler]:
    if not summary:
        return []
    out: list[ToolHandler] = []
    for h in summary.get("tool_handlers", []) or []:
        io = h.get("io_summary") or {}
        out.append(
            ToolHandler(
                name=h.get("name", ""),
                declared_description=h.get("declared_description"),
                declared_input_schema=h.get("declared_input_schema"),
                file=h.get("file", ""),
                line_start=h.get("line_start", 0),
                line_end=h.get("line_end", 0),
                callees_local=h.get("callees_local") or [],
                callees_imported=h.get("callees_imported") or [],
                string_literals=h.get("string_literals") or [],
                io_summary=IOSummary(
                    network_calls=[],  # truncated; downstream uses summary[...]
                    file_reads=[],
                    file_writes=[],
                    subprocess_calls=[],
                    env_reads=io.get("env_reads") or [],
                    crypto_calls=io.get("crypto_calls") or [],
                ),
            )
        )
    return out


async def save_findings(
    session: AsyncSession,
    server_id: UUID,
    artifact_ref: str,
    findings: list[Finding],
) -> list[UUID]:
    return await _upsert(session, server_id, artifact_ref, findings)


async def upsert_tool_capability(
    session: AsyncSession,
    tool_id: UUID,
    capabilities: list[str],
    classifier: str,
    content_hash: str,
) -> None:
    await session.execute(
        text(
            """
            INSERT INTO tool_capabilities
              (tool_id, classified_at, capabilities, classifier, content_hash)
            VALUES (:tid, now(), :caps, :clf, :hash)
            ON CONFLICT (tool_id) DO UPDATE
              SET capabilities = EXCLUDED.capabilities,
                  classifier   = EXCLUDED.classifier,
                  content_hash = EXCLUDED.content_hash,
                  classified_at = now()
            """
        ),
        {"tid": str(tool_id), "caps": capabilities, "clf": classifier, "hash": content_hash},
    )


async def get_cached_capability(
    session: AsyncSession, tool_id: UUID, content_hash: str
) -> list[str] | None:
    row = await session.execute(
        text(
            "SELECT capabilities FROM tool_capabilities "
            "WHERE tool_id = :tid AND content_hash = :h"
        ),
        {"tid": str(tool_id), "h": content_hash},
    )
    rec = row.first()
    return list(rec[0]) if rec and rec[0] else None
