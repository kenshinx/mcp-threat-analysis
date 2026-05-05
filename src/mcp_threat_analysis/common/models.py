"""Shared data contracts across static_analysis / semantic_analysis / risk_scoring.

Aligned with master design doc §3.1, plus risk_scoring lifecycle additions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

Severity = Literal["info", "low", "medium", "high", "critical"]
Layer = Literal[
    "static_analysis",
    "semantic_analysis",
    "runtime_analysis",
    "network_analysis",
    "remote_analysis",
]
FindingStatus = Literal[
    "active", "suppressed", "superseded", "confirmed", "false_positive"
]
ArtifactType = Literal["npm_tarball", "pypi_wheel", "docker_image", "github_archive"]


@dataclass(slots=True)
class ScanTarget:
    server_id: UUID
    version: str
    artifact_type: ArtifactType
    artifact_path: str  # local path or s3:// URL
    primary_lang: str
    declared_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def artifact_ref(self) -> str:
        return f"{self.server_id}:{self.version}"


@dataclass(slots=True)
class NetworkCall:
    func: str
    url_arg_kind: Literal["literal", "var", "tainted"]
    url_literal: str | None
    line: int


@dataclass(slots=True)
class FileOp:
    func: str
    path_arg_kind: Literal["literal", "var", "tainted"]
    path_literal: str | None
    mode: str | None
    line: int


@dataclass(slots=True)
class SubprocessCall:
    func: str
    cmd_arg_kind: Literal["literal", "var", "tainted"]
    cmd_literal: str | None
    line: int


@dataclass(slots=True)
class IOSummary:
    network_calls: list[NetworkCall] = field(default_factory=list)
    file_reads: list[FileOp] = field(default_factory=list)
    file_writes: list[FileOp] = field(default_factory=list)
    subprocess_calls: list[SubprocessCall] = field(default_factory=list)
    env_reads: list[str] = field(default_factory=list)
    crypto_calls: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImportRef:
    module: str
    symbol: str | None


@dataclass(slots=True)
class ToolHandler:
    name: str
    declared_description: str | None
    declared_input_schema: dict[str, Any] | None
    file: str
    line_start: int
    line_end: int
    callees_local: list[str] = field(default_factory=list)
    callees_imported: list[ImportRef] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    io_summary: IOSummary = field(default_factory=IOSummary)


@dataclass(slots=True)
class Dependency:
    registry: str
    name: str
    version: str | None


@dataclass(slots=True)
class StaticSummary:
    server_id: UUID
    version: str
    tool_handlers: list[ToolHandler]
    string_literals: list[str]
    declared_egress_domains: list[str]
    obfuscation_score: float
    manifest_facts: dict[str, Any]
    sca_dep_list: list[Dependency]


@dataclass(slots=True)
class Finding:
    detector: str
    layer: Layer
    severity: Severity
    confidence: float
    evidence: dict[str, Any]
    artifact_ref: str
    server_id: UUID | None = None
    issue_code: str | None = None
    id: UUID | None = None
    status: FindingStatus = "active"
    created_at: datetime | None = None

    def evidence_key(self) -> str:
        ev = self.evidence or {}
        return ev.get("evidence_key") or f"{ev.get('file','')}:{ev.get('line','')}:{ev.get('tool_name','')}"


@dataclass(slots=True)
class WorkDir:
    """Output of static_analysis target_loader."""
    root_path: Path
    primary_lang: str
    lang_files: dict[str, list[Path]]

    def find(self, names: list[str]) -> list[Path]:
        out: list[Path] = []
        for p in self.root_path.rglob("*"):
            if p.is_file() and p.name in names:
                out.append(p)
        return out
