"""Shared finding-write helpers used by static_analysis / semantic_analysis / risk_scoring."""
from __future__ import annotations

import json
from typing import Iterable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Finding


async def upsert_findings(
    session: AsyncSession,
    server_id: UUID,
    artifact_ref: str,
    findings: Iterable[Finding],
) -> list[UUID]:
    """Insert findings and supersede prior matching active rows.

    Match key: (server_id, detector, artifact_ref, evidence_key).
    """
    inserted: list[UUID] = []
    for f in findings:
        # Mark prior duplicates as superseded.
        await session.execute(
            text(
                """
                UPDATE findings
                   SET status = 'superseded',
                       status_changed_at = now()
                 WHERE server_id = :sid
                   AND detector = :det
                   AND artifact_ref = :ar
                   AND COALESCE(evidence->>'evidence_key', '') = :ek
                   AND status = 'active'
                """
            ),
            {
                "sid": str(server_id),
                "det": f.detector,
                "ar": artifact_ref,
                "ek": f.evidence_key(),
            },
        )

        evidence = dict(f.evidence or {})
        evidence.setdefault("evidence_key", f.evidence_key())

        row = await session.execute(
            text(
                """
                INSERT INTO findings
                  (server_id, detector, layer, issue_code, severity,
                   confidence, evidence, artifact_ref, status)
                VALUES
                  (:sid, :det, :layer, :ic, :sev, :conf,
                   CAST(:ev AS JSONB), :ar, 'active')
                RETURNING id
                """
            ),
            {
                "sid": str(server_id),
                "det": f.detector,
                "layer": f.layer,
                "ic": f.issue_code,
                "sev": f.severity,
                "conf": f.confidence,
                "ev": json.dumps(evidence),
                "ar": artifact_ref,
            },
        )
        inserted.append(row.scalar_one())
    return inserted


async def load_active_findings(
    session: AsyncSession, server_id: UUID
) -> list[dict]:
    rows = await session.execute(
        text(
            """
            SELECT id, detector, layer, issue_code, severity,
                   confidence, evidence, artifact_ref, status, created_at
              FROM findings
             WHERE server_id = :sid AND status = 'active'
            """
        ),
        {"sid": str(server_id)},
    )
    return [dict(r._mapping) for r in rows.all()]
