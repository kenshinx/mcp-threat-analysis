"""static_analysis-internal data structures."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.models import Finding, ToolHandler
from .extractors.string_extractor import StringBag


@dataclass(slots=True)
class StaticAnalysisContext:
    """In-memory state shared between extractors and analyzers in one run."""

    tool_handlers: list[ToolHandler] = field(default_factory=list)
    string_bag: StringBag = field(default_factory=StringBag)
    declared_egress_domains: list[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    manifest_facts: dict = field(default_factory=dict)
    sca_deps: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class StaticAnalysisResult:
    findings: list[Finding]
    context: StaticAnalysisContext
