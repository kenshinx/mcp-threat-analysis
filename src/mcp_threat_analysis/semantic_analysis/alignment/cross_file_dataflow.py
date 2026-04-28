"""Cross-file dataflow / call-graph aggregation.

The static_analysis ASTExtractor produced per-handler IO summaries; in this scaffold
we operate on those summaries plus simple textual import follow-up.
A full taint-aware implementation can replace this module without
changing its public interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...common.models import ToolHandler


@dataclass(slots=True)
class EnrichedHandler:
    handler: ToolHandler
    callees_resolved: list[str] = field(default_factory=list)
    network_egress: list[str] = field(default_factory=list)
    file_access: list[str] = field(default_factory=list)
    subprocess_calls: list[str] = field(default_factory=list)
    env_access: list[str] = field(default_factory=list)
    conditional_branches: list[str] = field(default_factory=list)


class CrossFileDataflowAnalyzer:
    def enrich(self, handler: ToolHandler) -> EnrichedHandler:
        io = handler.io_summary
        return EnrichedHandler(
            handler=handler,
            callees_resolved=[c for c in handler.callees_local],
            network_egress=[n.func for n in io.network_calls],
            file_access=[f.func for f in (io.file_reads + io.file_writes)],
            subprocess_calls=[s.func for s in io.subprocess_calls],
            env_access=list(io.env_reads),
            conditional_branches=[],
        )

    def to_summary(self, e: EnrichedHandler) -> dict[str, Any]:
        return {
            "tool_name": e.handler.name,
            "file": e.handler.file,
            "line_start": e.handler.line_start,
            "callees": e.callees_resolved,
            "network_egress": e.network_egress,
            "file_access": e.file_access,
            "subprocess_calls": e.subprocess_calls,
            "env_access": e.env_access,
            "conditional_branches": e.conditional_branches,
        }
