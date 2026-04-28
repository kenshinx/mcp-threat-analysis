"""Single-server Toxic Flow pattern detection."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ...common.logging import get_logger
from ...common.models import Finding
from ..llm import LLMClient, LLMUnavailable
from ..models import SemanticAnalysisContext, ToolSnapshot
from ..persistence import get_cached_capability, upsert_tool_capability
from ..prompts import load_prompt
from .base import Detector

log = get_logger(__name__)

TOXIC_FLOW_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "untrusted-read-to-sensitive-write",
        "sources": ["fetch_url", "read_email", "search_web"],
        "sinks": ["send_email", "execute_shell", "write_file"],
        "severity": "high",
    },
    {
        "name": "sensitive-read-to-external-write",
        "sources": ["read_file", "read_database", "read_secret"],
        "sinks": ["http_post", "send_email", "fetch_url"],
        "severity": "high",
    },
    {
        "name": "untrusted-desc-triggers-sensitive",
        "sources": ["fetch_url", "search_web"],
        "sinks": ["execute_shell", "write_file", "send_email"],
        "severity": "medium",
    },
]

CAPABILITY_VOCAB = sorted(
    {c for p in TOXIC_FLOW_PATTERNS for c in p["sources"] + p["sinks"]}
)


class ToxicFlowDetector(Detector):
    name = "toxic-flow"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()
        self.prompt = load_prompt("tool_capability_classification.md")

    async def run(self, session: AsyncSession, ctx: SemanticAnalysisContext) -> list[Finding]:
        capabilities: dict[str, list[str]] = {}
        for tool in ctx.tools:
            caps = await self._classify(session, tool)
            capabilities[tool.name] = caps

        out: list[Finding] = []
        for pattern in TOXIC_FLOW_PATTERNS:
            sources = [
                t for t, c in capabilities.items()
                if any(s in c for s in pattern["sources"])
            ]
            sinks = [
                t for t, c in capabilities.items()
                if any(s in c for s in pattern["sinks"])
            ]
            if sources and sinks:
                out.append(
                    Finding(
                        detector=f"toxic-flow:{pattern['name']}",
                        layer="semantic_analysis",
                        issue_code="ToxicFlows",
                        severity=pattern["severity"],
                        confidence=0.65,
                        evidence={
                            "pattern": pattern["name"],
                            "sources": sources,
                            "sinks": sinks,
                            "evidence_key": f"toxic-flow:{pattern['name']}:{ctx.server_id}",
                        },
                        artifact_ref=ctx.artifact_ref,
                        server_id=ctx.server_id,
                    )
                )
        return out

    async def _classify(
        self, session: AsyncSession, tool: ToolSnapshot
    ) -> list[str]:
        if not tool.tool_id:
            return []
        content_hash = hashlib.sha256(
            json.dumps(
                {"d": tool.description, "s": tool.input_schema}, sort_keys=True, default=str
            ).encode("utf-8")
        ).hexdigest()
        cached = await get_cached_capability(session, tool.tool_id, content_hash)
        if cached is not None:
            return cached
        try:
            resp = await self.llm.call(
                detector="tool-capability",
                prompt=self.prompt,
                payload=json.dumps(
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "vocab": CAPABILITY_VOCAB,
                    },
                    ensure_ascii=False,
                ),
                max_tokens=300,
            )
        except LLMUnavailable:
            return []
        except Exception:
            log.exception("toxic-flow.classify_failed", tool=tool.name)
            return []
        caps = resp.parsed.get("capabilities") if isinstance(resp.parsed, dict) else []
        caps = [c for c in (caps or []) if c in CAPABILITY_VOCAB]
        try:
            await upsert_tool_capability(
                session,
                tool.tool_id,
                caps,
                f"llm:{resp.model}",
                content_hash,
            )
        except Exception:
            log.exception("toxic-flow.cache_failed", tool=tool.name)
        return caps
