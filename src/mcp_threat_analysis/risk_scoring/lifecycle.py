"""Finding lifecycle transitions."""
from __future__ import annotations

from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

LifecycleAction = Literal[
    "suppress", "confirm_malicious", "confirm_vuln", "mark_fp", "reactivate"
]


class Lifecycle:
    async def suppress(
        self, session: AsyncSession, finding_id: UUID, reason: str
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE findings
                   SET status = 'suppressed',
                       status_changed_at = now(),
                       suppressed_reason = :r
                 WHERE id = :id
                """
            ),
            {"id": str(finding_id), "r": reason},
        )

    async def confirm(
        self, session: AsyncSession, finding_id: UUID
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE findings
                   SET status = 'confirmed',
                       status_changed_at = now()
                 WHERE id = :id
                """
            ),
            {"id": str(finding_id)},
        )

    async def mark_fp(
        self, session: AsyncSession, finding_id: UUID, reason: str
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE findings
                   SET status = 'false_positive',
                       status_changed_at = now(),
                       suppressed_reason = :r
                 WHERE id = :id
                """
            ),
            {"id": str(finding_id), "r": reason},
        )

    async def reactivate(
        self, session: AsyncSession, finding_id: UUID
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE findings
                   SET status = 'active',
                       status_changed_at = now(),
                       suppressed_reason = NULL
                 WHERE id = :id
                """
            ),
            {"id": str(finding_id)},
        )
