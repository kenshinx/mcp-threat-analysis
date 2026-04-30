"""Detector wrapper around AlignmentOrchestrator."""
from __future__ import annotations

import asyncio

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
    is_llm = True

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.alignment = AlignmentOrchestrator(llm=llm)

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        results = await asyncio.gather(
            *[self.alignment.run_one(ctx, tool) for tool in ctx.tools],
            return_exceptions=True,
        )
        return [
            f for f in results
            if f is not None and not isinstance(f, Exception)
        ]
