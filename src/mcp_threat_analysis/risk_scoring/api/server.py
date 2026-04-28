"""FastAPI HTTP read-API for risk_scoring: server risk + triage."""
from __future__ import annotations

import sys
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query

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
