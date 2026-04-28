"""LLM-based Tool Poisoning Attack semantic judgment."""
from __future__ import annotations

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

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()
        self.prompt = load_prompt("tpa_detection.md")

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            if len(tool.description or "") < 30:
                continue
            try:
                resp = await self.llm.call(
                    detector="tpa-llm",
                    prompt=self.prompt,
                    payload=_payload(tool),
                )
            except LLMUnavailable:
                log.info("tpa-llm.skip", reason="LLM unavailable")
                return out
            except Exception:
                log.exception("tpa-llm.error", tool=tool.name)
                continue
            verdict = (resp.parsed or {}).get("verdict", "clean")
            sev = _VERDICT_TO_SEVERITY.get(verdict)
            if not sev:
                continue
            out.append(
                Finding(
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
            )
        return out


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
