"""static_analysis: orchestrator — runs extractors then analyzers, persists results."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.db import session_scope
from ..common.logging import get_logger
from ..common.models import Finding, ScanTarget, WorkDir
from .analyzers import (
    Analyzer,
    CodeQLAnalyzer,
    ManifestAnalyzer,
    ObfuscationAnalyzer,
    ReputationAnalyzer,
    SCAAnalyzer,
    SecretAnalyzer,
    SemgrepAnalyzer,
)
from .extractors import ASTExtractor, StringExtractor, ToolHandlerLocator
from .models import StaticAnalysisContext, StaticAnalysisResult
from .persistence import save_static_findings
from .target_loader import TargetLoader

log = get_logger(__name__)


@dataclass(slots=True)
class StaticAnalysisConfig:
    enable_codeql: bool = True
    enable_reputation: bool = True


class StaticAnalysisOrchestrator:
    def __init__(
        self,
        config: StaticAnalysisConfig | None = None,
        analyzers: list[Analyzer] | None = None,
        loader: TargetLoader | None = None,
    ) -> None:
        self.config = config or StaticAnalysisConfig()
        self.loader = loader or TargetLoader()
        self.locator = ToolHandlerLocator()
        self.ast_extractor = ASTExtractor()
        self.string_extractor = StringExtractor()
        self.analyzers = analyzers or self._default_analyzers()

    def _default_analyzers(self) -> list[Analyzer]:
        a: list[Analyzer] = [
            ManifestAnalyzer(),
            ObfuscationAnalyzer(),
            SemgrepAnalyzer(),
            SecretAnalyzer(),
            SCAAnalyzer(),
        ]
        if self.config.enable_codeql:
            a.append(CodeQLAnalyzer())
        if self.config.enable_reputation:
            a.append(ReputationAnalyzer())
        return a

    async def run(
        self, target: ScanTarget, *, persist: bool = True
    ) -> StaticAnalysisResult:
        wd = self.loader.prepare(target)
        try:
            ctx = self._extract(wd)
            findings = await self._run_analyzers(wd, ctx, target)
            result = StaticAnalysisResult(findings=findings, context=ctx)
            if persist:
                async with session_scope() as session:
                    await save_static_findings(
                        session,
                        target.server_id,
                        target.version,
                        target.artifact_ref,
                        result,
                    )
            return result
        finally:
            self.loader.cleanup(wd)

    def _extract(self, wd: WorkDir) -> StaticAnalysisContext:
        ctx = StaticAnalysisContext()
        candidates = self.locator.locate(wd.lang_files)
        ctx.tool_handlers = self.ast_extractor.extract(candidates)
        ctx.string_bag = self.string_extractor.extract(wd.root_path)
        return ctx

    async def _run_analyzers(
        self, wd: WorkDir, ctx: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        out: list[Finding] = []
        for a in self.analyzers:
            try:
                hits = await a.analyze(wd, ctx, target)
                log.info("l2.analyzer.done", name=a.name, count=len(hits))
                out.extend(hits)
            except Exception:
                log.exception("l2.analyzer.crash", name=a.name)
        return out
