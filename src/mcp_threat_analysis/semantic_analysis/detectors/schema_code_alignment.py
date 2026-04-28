"""Detector wrapper around AlignmentOrchestrator."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.logging import get_logger
from ...common.models import Finding
from ..alignment import AlignmentOrchestrator
from ..llm import LLMClient
from ..models import SemanticAnalysisContext
from .base import Detector

log = get_logger(__name__)


class SchemaCodeAlignmentDetector(Detector):
    name = "schema-code-alignment"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.alignment = AlignmentOrchestrator(llm=llm)

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            f = await self.alignment.run_one(ctx, tool)
            if f is not None:
                out.append(f)
        return out
