"""Analyzer abstract base — every static_analysis detector must implement `analyze`."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ...common.models import Finding, ScanTarget, WorkDir
from ..extractors.string_extractor import StringBag
from ..models import StaticAnalysisContext


class Analyzer(ABC):
    name: str = "base"

    @abstractmethod
    async def analyze(
        self,
        workdir: WorkDir,
        context: StaticAnalysisContext,
        target: ScanTarget,
    ) -> list[Finding]:
        ...
