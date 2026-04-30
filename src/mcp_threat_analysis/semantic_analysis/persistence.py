"""semantic_analysis: persistence: load static_summary + tools, write findings."""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.db import session_scope
from ..common.logging import get_logger
from ..common.models import (
    Finding,
    FileOp,
    IOSummary,
    NetworkCall,
    SubprocessCall,
    ToolHandler,
)
from ..common.persistence import upsert_findings as _upsert
from .llm.cache import sha as _sha
from .models import ToolSnapshot

log = get_logger(__name__)


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
                    network_calls=[
                        NetworkCall(
                            func=n.get("func", ""),
                            url_arg_kind=n.get("url_arg_kind", "var"),
                            url_literal=n.get("url_literal"),
                            line=n.get("line", 0),
                        )
                        for n in (io.get("network_calls") or [])
                    ],
                    file_reads=[
                        FileOp(
                            func=f.get("func", ""),
                            path_arg_kind=f.get("path_arg_kind", "var"),
                            path_literal=f.get("path_literal"),
                            mode=f.get("mode"),
                            line=f.get("line", 0),
                        )
                        for f in (io.get("file_reads") or [])
                    ],
                    file_writes=[
                        FileOp(
                            func=f.get("func", ""),
                            path_arg_kind=f.get("path_arg_kind", "var"),
                            path_literal=f.get("path_literal"),
                            mode=f.get("mode"),
                            line=f.get("line", 0),
                        )
                        for f in (io.get("file_writes") or [])
                    ],
                    subprocess_calls=[
                        SubprocessCall(
                            func=s.get("func", ""),
                            cmd_arg_kind=s.get("cmd_arg_kind", "var"),
                            cmd_literal=s.get("cmd_literal"),
                            line=s.get("line", 0),
                        )
                        for s in (io.get("subprocess_calls") or [])
                    ],
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


async def insert_llm_call(
    *,
    detector: str,
    model: str,
    prompt: str,
    payload: str,
    tokens_in: int,
    tokens_out: int,
    cost_usd: float,
    status: str,
    response_json: dict[str, Any] | None = None,
    llm_call_id: UUID | None = None,
) -> UUID:
    """INSERT a row into llm_calls and return its id.

    Opens its own session_scope() so the caller does not need a DB session.
    Errors are logged but never raised — a failed write must not block the
    LLM pipeline.
    """
    call_id = llm_call_id or uuid4()
    try:
        async with session_scope() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO llm_calls
                      (id, detector, model, prompt_sha, input_sha,
                       tokens_in, tokens_out, cost_usd, status, response_json)
                    VALUES
                      (:id, :det, :model, :psha, :isha,
                       :tin, :tout, :cost, :status, CAST(:rj AS JSONB))
                    """
                ),
                {
                    "id": str(call_id),
                    "det": detector,
                    "model": model,
                    "psha": _sha(prompt),
                    "isha": _sha(payload),
                    "tin": tokens_in,
                    "tout": tokens_out,
                    "cost": cost_usd,
                    "status": status,
                    "rj": json.dumps(response_json) if response_json else None,
                },
            )
    except Exception:
        log.exception("llm_call.persist_failed", detector=detector, model=model)
    return call_id


async def link_llm_calls_to_findings(
    session: AsyncSession,
    finding_ids: list[UUID],
    findings: list[Finding],
) -> None:
    """UPDATE llm_calls.finding_id for findings that carry an llm_call_id in evidence."""
    for fid, finding in zip(finding_ids, findings):
        llm_call_id = (finding.evidence or {}).get("llm_call_id")
        if not llm_call_id:
            continue
        try:
            await session.execute(
                text(
                    "UPDATE llm_calls SET finding_id = :fid "
                    "WHERE id = :cid AND finding_id IS NULL"
                ),
                {"fid": str(fid), "cid": str(llm_call_id)},
            )
        except Exception:
            log.exception("llm_call.link_failed", llm_call_id=llm_call_id, finding_id=fid)
