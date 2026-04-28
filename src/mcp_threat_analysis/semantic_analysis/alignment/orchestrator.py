"""Coordinates the schema-code alignment pipeline for one tool at a time."""
from __future__ import annotations

from typing import Any

from ...common.logging import get_logger
from ...common.models import Finding
from ..llm import LLMClient, LLMUnavailable
from ..models import SemanticAnalysisContext, ToolSnapshot
from .cross_file_dataflow import CrossFileDataflowAnalyzer
from .prompt_builder import AlignmentPromptBuilder
from .response_validator import (
    AlignmentVerdict,
    InvalidAlignmentResponse,
    validate,
)

log = get_logger(__name__)


class AlignmentOrchestrator:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.dataflow = CrossFileDataflowAnalyzer()
        self.prompt_builder = AlignmentPromptBuilder()
        self.llm = llm or LLMClient()

    async def run_one(
        self, ctx: SemanticAnalysisContext, tool: ToolSnapshot
    ) -> Finding | None:
        if tool.handler is None:
            return None
        enriched = self.dataflow.enrich(tool.handler)
        io_summary = self.dataflow.to_summary(enriched)
        try:
            resp = await self.llm.call(
                detector="schema-code-alignment",
                prompt=self.prompt_builder.system_prompt(),
                payload=self.prompt_builder.user_payload(tool, io_summary),
                max_tokens=1500,
            )
        except LLMUnavailable:
            log.info("alignment.skip", reason="LLM unavailable")
            return None
        except Exception:
            log.exception("alignment.llm_failed", tool=tool.name)
            return None
        try:
            verdict = validate(resp.parsed or {})
        except InvalidAlignmentResponse as e:
            log.warning("alignment.invalid_response", tool=tool.name, reason=str(e))
            return None
        if verdict.alignment_score > 6:
            return None
        severity = (
            "critical" if verdict.alignment_score <= 3
            else "high" if verdict.alignment_score <= 5
            else "medium"
        )
        return Finding(
            detector="llm:schema-code-inconsistency",
            layer="semantic_analysis",
            issue_code="E001",
            severity=severity,  # type: ignore[arg-type]
            confidence=verdict.confidence,
            evidence={
                "tool_name": tool.name,
                "alignment_score": verdict.alignment_score,
                "behavioral_diff": verdict.behavioral_diff,
                "explanation": verdict.explanation,
                "io_summary": io_summary,
                "llm_model": resp.model,
                "evidence_key": f"alignment:{tool.name}",
            },
            artifact_ref=ctx.artifact_ref,
            server_id=ctx.server_id,
        )
