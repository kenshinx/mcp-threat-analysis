"""Popularity factor used to multiply server-level risk score."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class PopularityProvider:
    """Reads the latest popularity row for a server.

    The actual data ingestion (npm downloads, GitHub stars, registry
    indexes) is handled out-of-band by an L0/L1 task that writes to
    `server_popularity`. risk_scoring only reads.
    """

    async def get(self, session: AsyncSession, server_id: UUID) -> float:
        row = await session.execute(
            text("SELECT pop FROM server_popularity WHERE server_id = :sid"),
            {"sid": str(server_id)},
        )
        rec = row.first()
        if rec is None or rec[0] is None:
            return 0.0
        return max(0.0, min(1.0, float(rec[0])))

    @staticmethod
    def factor(pop: float) -> float:
        return 1.0 + max(0.0, min(1.0, pop))

    async def is_top_pct(
        self, session: AsyncSession, server_id: UUID, pct: float
    ) -> bool:
        # Ranks among rows with non-null pop. pct in (0..1).
        row = await session.execute(
            text(
                """
                WITH ranked AS (
                  SELECT server_id, pop,
                         percent_rank() OVER (ORDER BY pop DESC) AS pr
                  FROM server_popularity
                  WHERE pop IS NOT NULL
                )
                SELECT pr FROM ranked WHERE server_id = :sid
                """
            ),
            {"sid": str(server_id)},
        )
        rec = row.first()
        if rec is None or rec[0] is None:
            return False
        return float(rec[0]) <= pct
