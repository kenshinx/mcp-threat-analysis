"""Abstract MCP transport interface.

P1 only ships StreamableHTTPTransport; SSE and stdio transports will land in
P3 implementing the same surface so the orchestrator stays transport-agnostic.
"""
from __future__ import annotations

from typing import Protocol

from ..models import ProbeRequest, ProbeResult


class TransportError(Exception):
    """Raised by a transport when the probe cannot be completed.

    The orchestrator catches this, marks the observation ok=False, and stores
    the original message in the JSONB error column.
    """


class MCPTransport(Protocol):
    name: str

    async def probe(self, req: ProbeRequest) -> ProbeResult:  # pragma: no cover - protocol
        ...
