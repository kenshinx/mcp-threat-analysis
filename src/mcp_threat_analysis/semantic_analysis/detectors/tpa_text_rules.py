"""Promote static_analysis Semgrep text-rule findings into semantic_analysis with tool linkage.

We do not re-run Semgrep here. We read existing static_analysis findings whose detector
matches the text/TPA family and re-emit them as semantic_analysis findings with a
`tool_name` link when we can resolve it.
"""
from __future__ import annotations

from typing import Iterable

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from ...common.models import Finding
from ..models import SemanticAnalysisContext
from .base import Detector

_PROMOTE_DETECTORS = (
    "semgrep:tool-poisoning-",
    "semgrep:prompt-injection-",
    "semgrep:credential-harvesting-",
    "semgrep:data-exfil-",
    "semgrep:mcp-tool-bcc-pattern",
    "semgrep:mcp-prompt-injection-multilang",
)


class TPATextRulesDetector(Detector):
    name = "tpa-text"

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        rows = await session.execute(
            sql_text(
                """
                SELECT detector, severity, confidence, evidence, issue_code, artifact_ref
                  FROM findings
                 WHERE server_id = :sid
                   AND layer = 'static_analysis'
                   AND status = 'active'
                """
            ),
            {"sid": str(ctx.server_id)},
        )
        out: list[Finding] = []
        for r in rows.all():
            m = dict(r._mapping)
            if not _matches(m["detector"]):
                continue
            ev = dict(m["evidence"] or {})
            tool_name = ev.get("tool_name") or _resolve_by_file_line(
                ev.get("file"), ev.get("line"), ctx
            )
            ev["tool_name"] = tool_name
            ev["promoted_from"] = m["detector"]
            ev["evidence_key"] = (
                f"l3-promote:{m['detector']}:{tool_name or ''}:{ev.get('file','')}:{ev.get('line','')}"
            )
            out.append(
                Finding(
                    detector=m["detector"].replace("semgrep:", "tpa-rule:"),
                    layer="semantic_analysis",
                    issue_code=m["issue_code"] or "E001",
                    severity=m["severity"],
                    confidence=float(m["confidence"]),
                    evidence=ev,
                    artifact_ref=m["artifact_ref"] or ctx.artifact_ref,
                    server_id=ctx.server_id,
                )
            )
        return out


def _matches(detector: str) -> bool:
    return any(detector.startswith(p) for p in _PROMOTE_DETECTORS)


def _resolve_by_file_line(file: str | None, line: int | None, ctx: SemanticAnalysisContext) -> str | None:
    if not file or line is None:
        return None
    for h in ctx.handlers:
        if h.file == file and h.line_start <= line <= h.line_end:
            return h.name
    return None
