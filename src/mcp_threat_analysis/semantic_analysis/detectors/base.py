"""semantic_analysis: detector base."""
from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.models import Finding
from ..models import SemanticAnalysisContext


class Detector(ABC):
    name: str = "base"

    @abstractmethod
    async def run(
        self, session: AsyncSession, ctx: SemanticAnalysisContext
    ) -> list[Finding]:
        ...
