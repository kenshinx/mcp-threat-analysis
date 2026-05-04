"""semantic_analysis: orchestrator: assemble context, run detectors, persist findings."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID

from ..common.db import session_scope
from ..common.logging import get_logger
from ..common.models import Finding
from .detectors import (
    CharLayerDetector,
    Detector,
    SchemaCodeAlignmentDetector,
    ShadowingDetector,
    ToxicFlowDetector,
    TPALLMDetector,
    TPATextRulesDetector,
    UntrustedContentDetector,
)
from .llm import LLMClient
from .models import SemanticAnalysisContext, SemanticAnalysisResult
from .persistence import (
    hydrate_handlers,
    link_llm_calls_to_findings,
    load_static_summary,
    load_tools,
    save_findings,
)

log = get_logger(__name__)


@dataclass(slots=True)
class SemanticAnalysisConfig:
    enable_llm: bool = True


class SemanticAnalysisOrchestrator:
    def __init__(
        self,
        config: SemanticAnalysisConfig | None = None,
        detectors: list[Detector] | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self.config = config or SemanticAnalysisConfig()
        self.llm = llm or LLMClient()
        self.detectors = detectors or self._default_detectors()

    def _default_detectors(self) -> list[Detector]:
        ds: list[Detector] = [
            CharLayerDetector(),
            TPATextRulesDetector(),
            ShadowingDetector(),
            UntrustedContentDetector(),
        ]
        if self.config.enable_llm:
            ds.append(TPALLMDetector(llm=self.llm))
            ds.append(SchemaCodeAlignmentDetector(llm=self.llm))
            ds.append(ToxicFlowDetector(llm=self.llm))
        return ds

    async def run(
        self,
        server_id: UUID,
        version: str,
        artifact_ref: str | None = None,
        *,
        persist: bool = True,
    ) -> SemanticAnalysisResult:
        async with session_scope() as session:
            summary = await load_static_summary(session, server_id, version)
            handlers = hydrate_handlers(summary)
            tools = await load_tools(session, server_id)
            self._link_handlers(tools, handlers)
            ctx = SemanticAnalysisContext(
                server_id=server_id,
                version=version,
                artifact_ref=artifact_ref or f"{server_id}:{version}",
                tools=tools,
                handlers=handlers,
            )
            findings = await self._run_detectors(session, ctx)
            if persist:
                finding_ids = await save_findings(session, server_id, ctx.artifact_ref, findings)
                await link_llm_calls_to_findings(session, finding_ids, findings)
            return SemanticAnalysisResult(findings=findings)

    def _link_handlers(self, tools, handlers) -> None:
        by_name = {h.name: h for h in handlers}
        for t in tools:
            t.handler = by_name.get(t.name)

    async def _run_detectors(self, session, ctx: SemanticAnalysisContext) -> list[Finding]:
        results: list[Finding] = []
        rule_detectors = [d for d in self.detectors if not d.is_llm]
        llm_detectors = [d for d in self.detectors if d.is_llm]

        for d in rule_detectors:
            try:
                hits = await d.run(session, ctx)
                log.info("l3.detector.done", name=d.name, count=len(hits))
                results.extend(hits)
            except Exception:
                log.exception("l3.detector.crash", name=d.name)

        if llm_detectors:
            llm_results = await asyncio.gather(
                *[d.run(session, ctx) for d in llm_detectors],
                return_exceptions=True,
            )
            for d, res in zip(llm_detectors, llm_results):
                if isinstance(res, Exception):
                    log.warning("l3.detector.failed", name=d.name, err=str(res))
                    continue
                log.info("l3.detector.done", name=d.name, count=len(res))
                results.extend(res)

        return results
