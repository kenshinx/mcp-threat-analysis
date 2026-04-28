"""Read-side helpers used by the risk_scoring API."""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def get_server_risk(
    session: AsyncSession, server_id: UUID
) -> dict[str, Any] | None:
    row = await session.execute(
        text(
            """
            SELECT id, canonical_name, risk_score, risk_priority,
                   risk_updated_at, weights_version, status
              FROM servers WHERE id = :sid
            """
        ),
        {"sid": str(server_id)},
    )
    rec = row.first()
    return dict(rec._mapping) if rec else None


async def list_top_findings(
    session: AsyncSession, server_id: UUID, limit: int = 25
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            """
            SELECT id, detector, layer, severity, confidence, evidence,
                   issue_code, status, created_at
              FROM findings
             WHERE server_id = :sid AND status = 'active'
             ORDER BY
               CASE severity
                 WHEN 'critical' THEN 5
                 WHEN 'high' THEN 4
                 WHEN 'medium' THEN 3
                 WHEN 'low' THEN 2
                 WHEN 'info' THEN 1
               END DESC,
               confidence DESC
             LIMIT :lim
            """
        ),
        {"sid": str(server_id), "lim": limit},
    )
    return [dict(r._mapping) for r in rows.all()]


async def list_risk_history(
    session: AsyncSession, server_id: UUID, limit: int = 50
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            """
            SELECT scored_at, score, priority, finding_count, weights_version
              FROM server_risk_history
             WHERE server_id = :sid
             ORDER BY scored_at DESC
             LIMIT :lim
            """
        ),
        {"sid": str(server_id), "lim": limit},
    )
    return [dict(r._mapping) for r in rows.all()]


async def list_triage(
    session: AsyncSession,
    *,
    priority: str | None = None,
    status: str = "pending",
    limit: int = 100,
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            """
            SELECT t.id, t.server_id, s.canonical_name, t.priority, t.status,
                   t.enqueued_at, s.risk_score, t.assignee
              FROM triage_queue t
              JOIN servers s ON s.id = t.server_id
             WHERE t.status = :st
               AND (:prio IS NULL OR t.priority = :prio)
             ORDER BY t.enqueued_at ASC
             LIMIT :lim
            """
        ),
        {"prio": priority, "st": status, "lim": limit},
    )
    return [dict(r._mapping) for r in rows.all()]
