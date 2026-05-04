"""FastAPI HTTP read-API for risk_scoring: server risk + triage."""
from __future__ import annotations

import sys
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from ...common.db import session_scope
from ..lifecycle import Lifecycle
from ..persistence import (
    get_server_risk,
    list_risk_history,
    list_top_findings,
    list_triage,
)


def build_app() -> FastAPI:
    app = FastAPI(title="MCP Threat Analysis — risk_scoring API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:7137",
            "http://127.0.0.1:7137",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    lifecycle = Lifecycle()

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/servers/{server_id}/risk")
    async def server_risk(server_id: UUID):
        async with session_scope() as session:
            srv = await get_server_risk(session, server_id)
            if not srv:
                raise HTTPException(status_code=404, detail="server not found")
            top = await list_top_findings(session, server_id, limit=10)
            return {"server": srv, "top_findings": top}

    @app.get("/servers/{server_id}/risk/history")
    async def server_risk_history(server_id: UUID, limit: int = 50):
        async with session_scope() as session:
            return await list_risk_history(session, server_id, limit=limit)

    @app.get("/triage")
    async def triage(
        priority: str | None = Query(default=None),
        status: str = Query(default="pending"),
        limit: int = Query(default=100, le=1000),
    ):
        async with session_scope() as session:
            return await list_triage(
                session, priority=priority, status=status, limit=limit
            )

    @app.post("/findings/{finding_id}/suppress")
    async def suppress(finding_id: UUID, reason: str = ""):
        async with session_scope() as session:
            await lifecycle.suppress(session, finding_id, reason)
        return {"ok": True}

    @app.post("/findings/{finding_id}/confirm")
    async def confirm(finding_id: UUID):
        async with session_scope() as session:
            await lifecycle.confirm(session, finding_id)
        return {"ok": True}

    @app.post("/findings/{finding_id}/false-positive")
    async def fp(finding_id: UUID, reason: str = ""):
        async with session_scope() as session:
            await lifecycle.mark_fp(session, finding_id, reason)
        return {"ok": True}

    @app.get("/servers")
    async def list_servers():
        async with session_scope() as session:
            rows = await session.execute(
                text(
                    """
                    SELECT s.id, s.canonical_name, s.risk_score, s.risk_priority,
                           s.risk_updated_at, s.status,
                           (SELECT count(*) FROM findings f
                             WHERE f.server_id=s.id AND f.status='active') AS active_finding_count
                      FROM servers s
                     ORDER BY s.risk_score DESC NULLS LAST, s.canonical_name
                    """
                )
            )
            return [dict(r._mapping) for r in rows.all()]

    @app.get("/findings/{finding_id}")
    async def finding_detail(finding_id: UUID):
        async with session_scope() as session:
            row = await session.execute(
                text(
                    """
                    SELECT f.id, f.server_id, s.canonical_name,
                           f.detector, f.layer, f.severity, f.confidence,
                           f.evidence, f.issue_code, f.status,
                           f.created_at, f.artifact_ref
                      FROM findings f JOIN servers s ON s.id=f.server_id
                     WHERE f.id = :fid
                    """
                ),
                {"fid": str(finding_id)},
            )
            rec = row.first()
            if not rec:
                raise HTTPException(status_code=404, detail="finding not found")
            finding = dict(rec._mapping)
            llm_call = None
            llm_call_id = (finding.get("evidence") or {}).get("llm_call_id")
            if llm_call_id:
                lc = await session.execute(
                    text(
                        """
                        SELECT id, detector, model, prompt_sha, input_sha,
                               tokens_in, tokens_out, cost_usd, status,
                               response_json, created_at
                          FROM llm_calls WHERE id = :cid
                        """
                    ),
                    {"cid": llm_call_id},
                )
                lr = lc.first()
                if lr:
                    llm_call = dict(lr._mapping)
            related = await session.execute(
                text(
                    """
                    SELECT id, detector, layer, severity, confidence, status
                      FROM findings
                     WHERE server_id = :sid
                       AND id <> :fid
                       AND COALESCE(evidence->>'tool_name', '') = COALESCE(:tn, '')
                     ORDER BY layer, detector
                    """
                ),
                {
                    "sid": str(finding["server_id"]),
                    "fid": str(finding_id),
                    "tn": (finding.get("evidence") or {}).get("tool_name"),
                },
            )
            return {
                "finding": finding,
                "llm_call": llm_call,
                "related": [dict(r._mapping) for r in related.all()],
            }

    @app.get("/corpus/heatmap")
    async def corpus_heatmap():
        async with session_scope() as session:
            rows = await session.execute(
                text(
                    """
                    SELECT s.id AS server_id, s.canonical_name, s.risk_score,
                           f.layer, f.detector,
                           count(*) FILTER (WHERE f.status='active') AS n_active
                      FROM servers s
                      LEFT JOIN findings f ON f.server_id = s.id
                     GROUP BY s.id, s.canonical_name, s.risk_score, f.layer, f.detector
                     ORDER BY s.risk_score DESC NULLS LAST, f.layer, f.detector
                    """
                )
            )
            return [dict(r._mapping) for r in rows.all()]

    return app


def main() -> None:
    import uvicorn

    host = "0.0.0.0"
    port = 8080
    if len(sys.argv) >= 2 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    uvicorn.run(build_app(), host=host, port=port)


if __name__ == "__main__":
    main()
