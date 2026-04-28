"""W011 — untrusted content handling."""
from __future__ import annotations

import re

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.models import Finding
from ..models import SemanticAnalysisContext, ToolSnapshot
from .base import Detector

_UNTRUSTED_VERBS = re.compile(
    r"\b(fetch|search|browse|read[_\s]email|scrape|crawl|web[_\s]?fetch)\b", re.I
)
_SANITIZE_VERBS = re.compile(
    r"\b(escape|sanitize|strip[_\s]markdown|html\.escape|bleach\.\w+)\s*\(", re.I
)
_UNTRUSTED_MARKER = re.compile(r"\buntrusted|\bexternal[_\s]content\b", re.I)


class UntrustedContentDetector(Detector):
    name = "untrusted-content"

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            if not _UNTRUSTED_VERBS.search(tool.description or ""):
                continue
            has_marker = bool(
                _UNTRUSTED_MARKER.search(tool.description or "")
                or _UNTRUSTED_MARKER.search(_dump(tool.annotations))
            )
            has_sanitizer = self._handler_has_sanitizer(tool)
            if has_marker or has_sanitizer:
                continue
            out.append(
                Finding(
                    detector="untrusted-content:unmarked",
                    layer="semantic_analysis",
                    issue_code="W011",
                    severity="medium",
                    confidence=0.55,
                    evidence={
                        "tool_name": tool.name,
                        "evidence_key": f"untrusted:{tool.name}",
                        "reason": "tool returns external content without untrusted marker or sanitizer",
                    },
                    artifact_ref=ctx.artifact_ref,
                    server_id=ctx.server_id,
                )
            )
        return out

    def _handler_has_sanitizer(self, tool: ToolSnapshot) -> bool:
        if tool.handler is None:
            return False
        for s in tool.handler.string_literals:
            if _SANITIZE_VERBS.search(s):
                return True
        return False


def _dump(obj) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    try:
        import json

        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)
