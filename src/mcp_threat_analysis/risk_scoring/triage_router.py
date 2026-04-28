"""Routes aggregated risk into triage_queue and downstream events."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.logging import get_logger
from .aggregator import AggregateResult

log = get_logger(__name__)

_DEBOUNCE_HOURS = 24


class TriageRouter:
    async def route(
        self,
        session: AsyncSession,
        agg: AggregateResult,
    ) -> bool:
        """Enqueue the server for human triage if appropriate.

        Returns True when a new triage row is created (i.e. a P0/P1 alert
        the caller should also forward to L7).
        """
        if agg.score < 1.0 or agg.finding_count == 0:
            return False
        priority = _agg_priority(agg)
        if priority not in ("P0", "P1"):
            return False
        if await self._already_open(session, agg.server_id, priority):
            return False
        if await self._recent_resolution(session, agg.server_id, priority):
            return False
        await session.execute(
            text(
                """
                INSERT INTO triage_queue (server_id, priority, enqueued_at, status)
                VALUES (:sid, :prio, now(), 'pending')
                """
            ),
            {"sid": str(agg.server_id), "prio": priority},
        )
        log.info(
            "l6.triage.enqueued",
            server=str(agg.server_id),
            priority=priority,
            score=agg.score,
        )
        return True

    async def _already_open(
        self, session: AsyncSession, server_id: UUID, priority: str
    ) -> bool:
        row = await session.execute(
            text(
                """
                SELECT 1 FROM triage_queue
                 WHERE server_id = :sid AND priority = :prio
                   AND status IN ('pending','in_review')
                 LIMIT 1
                """
            ),
            {"sid": str(server_id), "prio": priority},
        )
        return row.first() is not None

    async def _recent_resolution(
        self, session: AsyncSession, server_id: UUID, priority: str
    ) -> bool:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=_DEBOUNCE_HOURS)
        row = await session.execute(
            text(
                """
                SELECT 1 FROM triage_queue
                 WHERE server_id = :sid AND priority = :prio
                   AND status = 'resolved'
                   AND resolved_at >= :cutoff
                 LIMIT 1
                """
            ),
            {"sid": str(server_id), "prio": priority, "cutoff": cutoff},
        )
        return row.first() is not None


def _agg_priority(agg: AggregateResult) -> str:
    # The aggregator already wrote a priority on `servers`; for routing we
    # recompute from the digest so this module is independently testable.
    has_critical_high_conf = any(
        f["severity"] == "critical" and f["confidence"] >= 0.9 for f in agg.top_findings
    )
    has_high = any(f["severity"] == "high" for f in agg.top_findings)
    if has_critical_high_conf:
        return "P0"
    if len({f["detector"] for f in agg.top_findings}) >= 3 and has_high:
        return "P0"
    if has_high or agg.score >= 30:
        return "P1"
    if any(f["severity"] == "medium" for f in agg.top_findings):
        return "P2"
    return "P3"
