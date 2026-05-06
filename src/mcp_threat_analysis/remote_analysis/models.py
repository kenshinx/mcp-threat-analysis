"""remote_analysis: internal types."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

PROBE_VERSION = "p1"


@dataclass(slots=True)
class TLSInfo:
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sha256: str | None = None
    self_signed: bool = False
    days_until_expiry: int | None = None
    san: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProbeRequest:
    endpoint: str
    transport: str = "streamable_http"
    headers: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 15.0


@dataclass(slots=True)
class ProbeResult:
    """Outcome of a single probe pass.

    `ok` is True when initialize + tools/list both succeeded; partial successes
    (e.g. resources/list 404) still leave ok=True. `error` is a dict so it can
    serialize directly into JSONB.
    """

    request: ProbeRequest
    ok: bool
    probed_at: datetime
    latency_ms: int
    protocol_ver: str | None = None
    server_info: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    tls: TLSInfo | None = None
    auth_kind: str = "none"  # 'none' | 'header' | 'oauth' | 'mtls'
    error: dict[str, Any] | None = None


@dataclass(slots=True)
class RemoteFinding:
    """Subset of common Finding for remote_analysis-layer detectors.

    Shape parallels semantic_analysis.detectors.* outputs so persistence can
    re-use upsert_findings.
    """

    detector: str
    severity: str           # 'info'|'low'|'medium'|'high'|'critical'
    confidence: float
    evidence: dict[str, Any]
    issue_code: str | None = None


@dataclass(slots=True)
class ScanOutcome:
    server_id: UUID
    canonical_name: str
    observation_id: UUID
    result: ProbeResult
    findings: list[RemoteFinding]
