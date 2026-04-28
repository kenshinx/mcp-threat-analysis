"""Tool name + semantic-description shadowing detection."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.logging import get_logger
from ...common.models import Finding
from ..embeddings import EmbeddingEncoder, ShadowingIndex
from ..models import SemanticAnalysisContext, ToolSnapshot
from .base import Detector

log = get_logger(__name__)


class ShadowingDetector(Detector):
    name = "shadowing"

    def __init__(self, encoder: EmbeddingEncoder | None = None) -> None:
        self.encoder = encoder or EmbeddingEncoder()

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        idx = ShadowingIndex(session)
        out: list[Finding] = []
        for tool in ctx.tools:
            if not tool.tool_id:
                continue
            emb = await self.encoder.encode(_text(tool))
            try:
                await idx.upsert(tool.tool_id, emb)
            except Exception:
                log.exception("shadow.upsert_failed", tool=tool.name)
            try:
                name_hits = await idx.by_name(tool.name, exclude_server_id=ctx.server_id)
            except Exception:
                name_hits = []
            for h in name_hits:
                out.append(_mk_name_finding(ctx, tool, h))
            try:
                desc_hits = await idx.by_description(emb, exclude_server_id=ctx.server_id)
            except Exception:
                desc_hits = []
            for h in desc_hits:
                out.append(_mk_desc_finding(ctx, tool, h))
        return out


def _text(t: ToolSnapshot) -> str:
    return f"{t.name}\n{t.description}".strip()


def _mk_name_finding(ctx: SemanticAnalysisContext, t: ToolSnapshot, hit: dict) -> Finding:
    same_name = (hit.get("name") or "").lower() == (t.name or "").lower()
    severity = "high" if same_name else "medium"
    return Finding(
        detector="shadow:name-collision",
        layer="semantic_analysis",
        issue_code="E002",
        severity=severity,
        confidence=0.85 if same_name else 0.7,
        evidence={
            "tool_name": t.name,
            "match_tool_id": str(hit.get("id")),
            "match_server_id": str(hit.get("server_id")),
            "match_name": hit.get("name"),
            "evidence_key": f"shadow:name:{t.name}:{hit.get('server_id')}",
        },
        artifact_ref=ctx.artifact_ref,
        server_id=ctx.server_id,
    )


def _mk_desc_finding(ctx: SemanticAnalysisContext, t: ToolSnapshot, hit: dict) -> Finding:
    return Finding(
        detector="shadow:semantic-clone",
        layer="semantic_analysis",
        issue_code="E002",
        severity="medium",
        confidence=float(hit.get("sim") or 0.93),
        evidence={
            "tool_name": t.name,
            "match_tool_id": str(hit.get("id")),
            "match_server_id": str(hit.get("server_id")),
            "match_name": hit.get("name"),
            "similarity": hit.get("sim"),
            "evidence_key": f"shadow:desc:{t.name}:{hit.get('id')}",
        },
        artifact_ref=ctx.artifact_ref,
        server_id=ctx.server_id,
    )
