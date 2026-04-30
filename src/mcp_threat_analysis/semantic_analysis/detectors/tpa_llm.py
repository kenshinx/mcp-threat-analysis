"""LLM-based Tool Poisoning Attack semantic judgment."""
from __future__ import annotations

import asyncio
import json

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.logging import get_logger
from ...common.models import Finding
from ..llm import LLMClient, LLMUnavailable
from ..models import SemanticAnalysisContext, ToolSnapshot
from ..prompts import load_prompt
from .base import Detector

log = get_logger(__name__)

_VERDICT_TO_SEVERITY = {
    "clean": None,
    "suspicious": "medium",
    "malicious": "critical",
}


class TPALLMDetector(Detector):
    name = "tpa-llm"
    is_llm = True

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()
        self.prompt = load_prompt("tpa_detection.md")

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        tools = [t for t in ctx.tools if len((t.description or "")) >= 30]
        if not tools:
            return []
        results = await asyncio.gather(
            *[self._analyze_tool(ctx, tool) for tool in tools],
            return_exceptions=True,
        )
        out: list[Finding] = []
        for tool, res in zip(tools, results):
            if isinstance(res, Exception):
                log.warning("tpa_llm.tool.failed", tool=tool.name, err=str(res))
                continue
            if res is not None:
                out.append(res)
        return out

    async def _analyze_tool(
        self, ctx: SemanticAnalysisContext, tool: ToolSnapshot
    ) -> Finding | None:
        try:
            resp = await self.llm.call(
                detector="tpa-llm",
                prompt=self.prompt,
                payload=_payload(tool),
            )
        except LLMUnavailable:
            log.info("tpa-llm.skip", reason="LLM unavailable")
            return None
        verdict = (resp.parsed or {}).get("verdict", "clean")
        sev = _VERDICT_TO_SEVERITY.get(verdict)
        if not sev:
            return None
        return Finding(
            detector="tpa-llm",
            layer="semantic_analysis",
            issue_code="E001",
            severity=sev,  # type: ignore[arg-type]
            confidence=float(resp.parsed.get("confidence", 0.7)),
            evidence={
                "tool_name": tool.name,
                "verdict": verdict,
                "categories": resp.parsed.get("categories"),
                "evidence_quotes": resp.parsed.get("evidence_quotes"),
                "explanation": resp.parsed.get("explanation"),
                "llm_model": resp.model,
                "evidence_key": f"tpa-llm:{tool.name}",
            },
            artifact_ref=ctx.artifact_ref,
            server_id=ctx.server_id,
        )


def _payload(tool: ToolSnapshot) -> str:
    return json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "annotations": tool.annotations,
        },
        ensure_ascii=False,
    )
