"""Polling-based ingestor that watches `findings.updated_at` and triggers
re-aggregation per affected server.

This is the "降级" path called out in the design doc; a CDC-based path can be
added later by feeding server_ids into `process_batch` instead.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.db import session_scope
from ..common.logging import get_logger
from .aggregator import Aggregator
from .triage_router import TriageRouter

log = get_logger(__name__)


@dataclass(slots=True)
class IngestorState:
    last_seen: datetime = field(
        default_factory=lambda: datetime.fromtimestamp(0, tz=timezone.utc)
    )


class Ingestor:
    def __init__(
        self,
        aggregator: Aggregator | None = None,
        triage_router: TriageRouter | None = None,
        poll_interval_s: float = 60.0,
    ) -> None:
        self.aggregator = aggregator or Aggregator()
        self.triage_router = triage_router or TriageRouter()
        self.poll_interval_s = poll_interval_s
        self.state = IngestorState()
        self._stopping = asyncio.Event()

    async def run_forever(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("l6.ingestor.tick_failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self.poll_interval_s
                )
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stopping.set()

    async def tick(self) -> int:
        async with session_scope() as session:
            new_servers, new_cursor = await self._poll_dirty(session)
            for sid in new_servers:
                await self.process_server(session, sid)
            self.state.last_seen = new_cursor
            return len(new_servers)

    async def _poll_dirty(
        self, session: AsyncSession
    ) -> tuple[list[UUID], datetime]:
        rows = await session.execute(
            text(
                """
                SELECT DISTINCT server_id, MAX(updated_at) AS last_change
                  FROM findings
                 WHERE updated_at > :cursor
                 GROUP BY server_id
                """
            ),
            {"cursor": self.state.last_seen},
        )
        out: list[UUID] = []
        cursor = self.state.last_seen
        for r in rows.all():
            m = r._mapping
            out.append(m["server_id"])
            if m["last_change"] and m["last_change"] > cursor:
                cursor = m["last_change"]
        return out, cursor

    async def process_server(
        self, session: AsyncSession, server_id: UUID
    ) -> None:
        agg = await self.aggregator.aggregate(session, server_id)
        await self.triage_router.route(session, agg)
        log.info(
            "l6.ingestor.processed",
            server=str(server_id),
            score=agg.score,
            count=agg.finding_count,
        )
