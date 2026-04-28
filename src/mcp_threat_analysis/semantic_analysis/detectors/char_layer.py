"""Character-layer anomalies in tool description / annotations.

Implements design doc §5.1.1 verbatim — pure rules, no LLM.
"""
from __future__ import annotations

import re
import unicodedata

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.models import Finding
from ..models import SemanticAnalysisContext, ToolSnapshot
from .base import Detector

_SUSPICIOUS_RANGES = [
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F),
]
_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


class CharLayerDetector(Detector):
    name = "char-layer"

    async def run(
        self, session: AsyncSession, ctx: SemanticAnalysisContext
    ) -> list[Finding]:
        out: list[Finding] = []
        for tool in ctx.tools:
            for field, text in self._fields(tool):
                if not text:
                    continue
                out.extend(self._scan(ctx, tool, field, text))
        return out

    def _fields(self, t: ToolSnapshot):
        yield "description", t.description
        yield "annotations", _stringify(t.annotations)
        yield "input_schema", _stringify(t.input_schema)

    def _scan(self, ctx: SemanticAnalysisContext, tool: ToolSnapshot, field: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        for i, ch in enumerate(text):
            cp = ord(ch)
            for lo, hi in _SUSPICIOUS_RANGES:
                if lo <= cp <= hi:
                    out.append(
                        Finding(
                            detector="char:hidden-unicode",
                            layer="semantic_analysis",
                            issue_code="E001",
                            severity="high",
                            confidence=0.95,
                            evidence={
                                "tool_name": tool.name,
                                "field": field,
                                "pos": i,
                                "codepoint": hex(cp),
                                "name": unicodedata.name(ch, ""),
                                "context": text[max(0, i - 30) : i + 30],
                                "evidence_key": f"char:unicode:{tool.name}:{field}:{i}",
                            },
                            artifact_ref=ctx.artifact_ref,
                            server_id=ctx.server_id,
                        )
                    )
                    break  # one finding per char
        if _ANSI.search(text):
            out.append(
                Finding(
                    detector="char:ansi-escape",
                    layer="semantic_analysis",
                    issue_code="E001",
                    severity="medium",
                    confidence=0.9,
                    evidence={
                        "tool_name": tool.name,
                        "field": field,
                        "evidence_key": f"char:ansi:{tool.name}:{field}",
                    },
                    artifact_ref=ctx.artifact_ref,
                    server_id=ctx.server_id,
                )
            )
        return out


def _stringify(obj) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    try:
        import json

        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)
