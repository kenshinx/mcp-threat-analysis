"""server.json / package.json / pyproject.toml audit."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ..models import StaticAnalysisContext
from .base import Analyzer

try:  # py 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

log = get_logger(__name__)

_NETWORK_OR_EXEC_RE = re.compile(
    r"\b(curl|wget|fetch|exec|eval|child_process|subprocess|os\.system|"
    r"https?://)\b"
)
_MCP_KEYWORD_RE = re.compile(r"\bmcp\b", re.I)
_MCP_DEP_RE = re.compile(
    r"@modelcontextprotocol/sdk|fastmcp|^mcp$|modelcontextprotocol", re.I
)


class ManifestAnalyzer(Analyzer):
    name = "manifest"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        findings: list[Finding] = []
        for p in workdir.find(["package.json"]):
            findings.extend(self._audit_package_json(p, target, context))
        for p in workdir.find(["pyproject.toml"]):
            findings.extend(self._audit_pyproject(p, target))
        for p in workdir.find(["server.json"]):
            findings.extend(self._audit_server_json(p, target, context))
        return findings

    def _audit_package_json(
        self, path: Path, target: ScanTarget, ctx: StaticAnalysisContext
    ) -> list[Finding]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        out: list[Finding] = []
        scripts = data.get("scripts", {}) or {}
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            cmd = scripts.get(hook)
            if cmd and _NETWORK_OR_EXEC_RE.search(cmd):
                out.append(
                    self._mk(
                        target,
                        "manifest:install-hook-network-or-exec",
                        "critical",
                        0.85,
                        {
                            "file": str(path),
                            "hook": hook,
                            "cmd": cmd,
                            "evidence_key": f"npm-hook:{hook}",
                        },
                    )
                )
        bin_ = data.get("bin")
        if isinstance(bin_, str) and bin_.startswith(("http://", "https://")):
            out.append(
                self._mk(
                    target,
                    "manifest:bin-remote-url",
                    "high",
                    0.9,
                    {"file": str(path), "bin": bin_, "evidence_key": "npm-bin-url"},
                )
            )
        keywords = data.get("keywords") or []
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        if any(_MCP_KEYWORD_RE.search(k or "") for k in keywords) and not any(
            _MCP_DEP_RE.search(d) for d in deps
        ):
            out.append(
                self._mk(
                    target,
                    "manifest:fake-mcp-package",
                    "low",
                    0.6,
                    {"file": str(path), "evidence_key": "fake-mcp"},
                )
            )
        ctx.manifest_facts["package_json"] = {
            "name": data.get("name"),
            "version": data.get("version"),
            "publisher_repo": (data.get("repository") or {}).get("url")
            if isinstance(data.get("repository"), dict)
            else data.get("repository"),
        }
        return out

    def _audit_pyproject(self, path: Path, target: ScanTarget) -> list[Finding]:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        out: list[Finding] = []
        scripts = ((data.get("project") or {}).get("scripts") or {})
        for k, v in scripts.items():
            if isinstance(v, str) and _NETWORK_OR_EXEC_RE.search(v):
                out.append(
                    self._mk(
                        target,
                        "manifest:py-script-network-or-exec",
                        "high",
                        0.7,
                        {
                            "file": str(path),
                            "entry": k,
                            "cmd": v,
                            "evidence_key": f"py-script:{k}",
                        },
                    )
                )
        return out

    def _audit_server_json(
        self, path: Path, target: ScanTarget, ctx: StaticAnalysisContext
    ) -> list[Finding]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return [
                self._mk(
                    target,
                    "manifest:server-json-invalid",
                    "low",
                    0.7,
                    {"file": str(path), "evidence_key": "server-json-invalid"},
                )
            ]
        if not isinstance(data, dict):
            return []
        # Capture declared egress for downstream usage.
        egress = data.get("egress") or data.get("declared_egress") or []
        if isinstance(egress, list):
            ctx.declared_egress_domains.extend(str(x) for x in egress)
        return []

    def _mk(
        self,
        target: ScanTarget,
        detector: str,
        severity: str,
        confidence: float,
        evidence: dict,
    ) -> Finding:
        return Finding(
            detector=detector,
            layer="static_analysis",
            issue_code=None,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,
            evidence=evidence,
            artifact_ref=target.artifact_ref,
            server_id=target.server_id,
        )
