"""semantic_analysis: internal types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from ..common.models import Finding, ToolHandler


@dataclass(slots=True)
class ToolSnapshot:
    """A normalized view of a tool from tools/list + DB tools row."""

    tool_id: UUID | None
    server_id: UUID
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    handler: ToolHandler | None  # Linked from static_analysis static_summary when available


@dataclass(slots=True)
class SemanticAnalysisContext:
    server_id: UUID
    version: str
    artifact_ref: str
    tools: list[ToolSnapshot] = field(default_factory=list)
    handlers: list[ToolHandler] = field(default_factory=list)


@dataclass(slots=True)
class SemanticAnalysisResult:
    findings: list[Finding]
