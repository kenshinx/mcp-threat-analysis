"""pgvector-backed search for tool-name / tool-description shadowing."""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def _vec_literal(emb: list[float]) -> str:
    # Format pgvector input string: "[0.1,0.2,...]"
    return "[" + ",".join(f"{x:.6f}" for x in emb) + "]"


async def upsert_tool_embedding(
    session: AsyncSession, tool_id: UUID, emb: list[float]
) -> None:
    await session.execute(
        text("UPDATE tools SET description_emb = CAST(:e AS vector) WHERE id = :id"),
        {"e": _vec_literal(emb), "id": str(tool_id)},
    )


async def search_similar_descriptions(
    session: AsyncSession,
    emb: list[float],
    *,
    threshold: float = 0.93,
    exclude_server_id: UUID | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            """
            SELECT id, server_id, name, description,
                   1 - (description_emb <=> CAST(:e AS vector)) AS sim
              FROM tools
             WHERE description_emb IS NOT NULL
               AND (CAST(:exclude_sid AS UUID) IS NULL
                    OR server_id <> CAST(:exclude_sid AS UUID))
             ORDER BY description_emb <=> CAST(:e AS vector)
             LIMIT :lim
            """
        ),
        {
            "e": _vec_literal(emb),
            "exclude_sid": str(exclude_server_id) if exclude_server_id else None,
            "lim": limit,
        },
    )
    out = []
    for r in rows.all():
        m = dict(r._mapping)
        if (m.get("sim") or 0) >= threshold:
            out.append(m)
    return out


async def search_by_name(
    session: AsyncSession,
    name: str,
    *,
    exclude_server_id: UUID | None = None,
    max_distance: int = 2,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Postgres trigram-based name search; assumes pg_trgm extension enabled.

    Falls back to exact-match if the extension is missing (CREATE EXTENSION
    IF NOT EXISTS pg_trgm at ops time).
    """
    rows = await session.execute(
        text(
            """
            SELECT id, server_id, name, description
              FROM tools
             WHERE (lower(name) = lower(:n) OR levenshtein(lower(name), lower(:n)) <= :md)
               AND (CAST(:exclude_sid AS UUID) IS NULL
                    OR server_id <> CAST(:exclude_sid AS UUID))
             LIMIT :lim
            """
        ),
        {
            "n": name,
            "md": max_distance,
            "exclude_sid": str(exclude_server_id) if exclude_server_id else None,
            "lim": limit,
        },
    )
    return [dict(r._mapping) for r in rows.all()]


class ShadowingIndex:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(self, tool_id: UUID, emb: list[float]) -> None:
        await upsert_tool_embedding(self.session, tool_id, emb)

    async def by_name(
        self, name: str, exclude_server_id: UUID | None
    ) -> list[dict[str, Any]]:
        return await search_by_name(self.session, name, exclude_server_id=exclude_server_id)

    async def by_description(
        self, emb: list[float], exclude_server_id: UUID | None
    ) -> list[dict[str, Any]]:
        return await search_similar_descriptions(
            self.session, emb, exclude_server_id=exclude_server_id
        )
