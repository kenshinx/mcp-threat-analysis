"""Software Composition Analysis: OSV-Scanner, npm audit, pip-audit."""
from __future__ import annotations

import json
import shutil

from ...common.config import get_settings
from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ...common.subprocess_runner import AnalyzerTimeout, run
from ..models import StaticAnalysisContext
from .base import Analyzer

log = get_logger(__name__)

_CVSS_TO_SEV = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def _cvss_to_severity(score: float) -> str:
    for cutoff, sev in _CVSS_TO_SEV:
        if score >= cutoff:
            return sev
    return "info"


class SCAAnalyzer(Analyzer):
    name = "sca"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        findings: list[Finding] = []
        if shutil.which(get_settings().osv_scanner_bin):
            findings.extend(await self._osv(workdir, target))
        if (workdir.root_path / "package.json").exists() and shutil.which(
            get_settings().npm_bin
        ):
            findings.extend(await self._npm(workdir, target))
        if (workdir.root_path / "requirements.txt").exists() and shutil.which(
            get_settings().pip_audit_bin
        ):
            findings.extend(await self._pip(workdir, target))
        return self._dedupe(findings)

    async def _osv(self, workdir: WorkDir, target: ScanTarget) -> list[Finding]:
        try:
            res = await run(
                [get_settings().osv_scanner_bin, "--json", "--recursive", str(workdir.root_path)],
                timeout_s=180,
            )
        except AnalyzerTimeout:
            return []
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for r in data.get("results", []):
            for pkg in r.get("packages", []):
                p = pkg.get("package", {})
                for v in pkg.get("vulnerabilities", []):
                    cvss = _max_cvss(v)
                    sev = _cvss_to_severity(cvss) if cvss else "medium"
                    out.append(
                        Finding(
                            detector=f"sca:osv:{v.get('id','unknown')}",
                            layer="static_analysis",
                            issue_code=v.get("id"),
                            severity=sev,
                            confidence=0.95,
                            evidence={
                                "package": p.get("name"),
                                "version": p.get("version"),
                                "ecosystem": p.get("ecosystem"),
                                "advisory": v.get("id"),
                                "cvss": cvss,
                                "summary": v.get("summary"),
                                "evidence_key": f"osv:{p.get('name')}:{p.get('version')}:{v.get('id')}",
                            },
                            artifact_ref=target.artifact_ref,
                            server_id=target.server_id,
                        )
                    )
                    context.sca_deps.append(
                        {
                            "registry": p.get("ecosystem", "").lower(),
                            "name": p.get("name"),
                            "version": p.get("version"),
                        }
                    )
        return out

    async def _npm(self, workdir: WorkDir, target: ScanTarget) -> list[Finding]:
        try:
            res = await run(
                [get_settings().npm_bin, "audit", "--json", "--package-lock-only"],
                cwd=workdir.root_path,
                timeout_s=180,
            )
        except AnalyzerTimeout:
            return []
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for name, vuln in (data.get("vulnerabilities") or {}).items():
            sev = vuln.get("severity", "medium")
            out.append(
                Finding(
                    detector=f"sca:npm:{name}",
                    layer="static_analysis",
                    issue_code=None,
                    severity=sev if sev in ("info", "low", "medium", "high", "critical") else "medium",
                    confidence=0.9,
                    evidence={
                        "package": name,
                        "via": vuln.get("via"),
                        "evidence_key": f"npm:{name}",
                    },
                    artifact_ref=target.artifact_ref,
                    server_id=target.server_id,
                )
            )
        return out

    async def _pip(self, workdir: WorkDir, target: ScanTarget) -> list[Finding]:
        try:
            res = await run(
                [
                    get_settings().pip_audit_bin,
                    "--strict",
                    "--format=json",
                    "-r",
                    str(workdir.root_path / "requirements.txt"),
                ],
                timeout_s=180,
            )
        except AnalyzerTimeout:
            return []
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                out.append(
                    Finding(
                        detector=f"sca:pip-audit:{v.get('id')}",
                        layer="static_analysis",
                        issue_code=v.get("id"),
                        severity="high",
                        confidence=0.95,
                        evidence={
                            "package": dep.get("name"),
                            "version": dep.get("version"),
                            "advisory": v.get("id"),
                            "fix_versions": v.get("fix_versions"),
                            "evidence_key": f"pip:{dep.get('name')}:{dep.get('version')}:{v.get('id')}",
                        },
                        artifact_ref=target.artifact_ref,
                        server_id=target.server_id,
                    )
                )
        return out

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        out: list[Finding] = []
        for f in findings:
            k = f.evidence.get("evidence_key") or f.detector
            if k in seen:
                continue
            seen.add(k)
            out.append(f)
        return out


def _max_cvss(vuln: dict) -> float:
    best = 0.0
    for s in vuln.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V"):
            try:
                from cvss import CVSS3  # type: ignore

                best = max(best, CVSS3(s["score"]).base_score)
            except Exception:
                continue
    return best
