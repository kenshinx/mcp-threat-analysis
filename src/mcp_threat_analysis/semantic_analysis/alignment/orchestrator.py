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
        # Skip when the tool ships no human-facing declaration. With an empty
        # description and no annotations the LLM has nothing to align the
        # implementation against and consistently returns critical
        # "fully undeclared" verdicts on perfectly benign tools (TS fixtures
        # using the 3-arg server.tool(name, schema, handler) form). The
        # tool.name + input_schema alone are not a behavioral contract.
        declared_desc = (tool.description or "").strip()
        declared_handler_desc = (
            (tool.handler.declared_description or "").strip() if tool.handler else ""
        )
        has_annotations = bool(tool.annotations)
        if not declared_desc and not declared_handler_desc and not has_annotations:
            log.info("alignment.skip", tool=tool.name, reason="no declaration")
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
        # Tighter than the prompt contract (which calls score<=6 "suspicious").
        # Empirically, scores 4-6 produced by the current prompt include too
        # many "minor undeclared field"-class findings on benign tools to be
        # actionable. Keep only score<=3 (clear behavioral mismatch).
        if verdict.alignment_score > 3:
            return None
        severity = (
            "critical" if verdict.alignment_score <= 1
            else "high" if verdict.alignment_score <= 2
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
                "llm_call_id": str(resp.llm_call_id) if resp.llm_call_id else None,
                "evidence_key": f"alignment:{tool.name}",
            },
            artifact_ref=ctx.artifact_ref,
            server_id=ctx.server_id,
        )
