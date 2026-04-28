"""Secret scanning using TruffleHog (preferred) and Gitleaks (fallback)."""
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


class SecretAnalyzer(Analyzer):
    name = "secret"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._run_trufflehog(workdir, target))
        findings.extend(await self._run_gitleaks(workdir, target))
        return self._dedupe(findings)

    async def _run_trufflehog(
        self, workdir: WorkDir, target: ScanTarget
    ) -> list[Finding]:
        bin_ = get_settings().trufflehog_bin
        if not shutil.which(bin_):
            return []
        try:
            res = await run(
                [bin_, "filesystem", "--json", "--no-update", str(workdir.root_path)],
                timeout_s=180,
            )
        except AnalyzerTimeout:
            return []
        out: list[Finding] = []
        for line in res.stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            verified = bool(rec.get("Verified"))
            sm = rec.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file = sm.get("file")
            line_no = sm.get("line", 0)
            kind = rec.get("DetectorName", "secret")
            out.append(
                Finding(
                    detector=f"secret:trufflehog:{kind}",
                    layer="static_analysis",
                    issue_code="CWE-798",
                    severity="critical" if verified else "medium",
                    confidence=0.95 if verified else 0.6,
                    evidence={
                        "file": file,
                        "line": line_no,
                        "detector_name": kind,
                        "verified": verified,
                        "evidence_key": f"trufflehog:{kind}:{file}:{line_no}",
                    },
                    artifact_ref=target.artifact_ref,
                    server_id=target.server_id,
                )
            )
        return out

    async def _run_gitleaks(
        self, workdir: WorkDir, target: ScanTarget
    ) -> list[Finding]:
        bin_ = get_settings().gitleaks_bin
        if not shutil.which(bin_):
            return []
        try:
            res = await run(
                [
                    bin_,
                    "detect",
                    "--no-git",
                    "--report-format=json",
                    "--report-path=/dev/stdout",
                    "--source",
                    str(workdir.root_path),
                ],
                timeout_s=180,
            )
        except AnalyzerTimeout:
            return []
        out: list[Finding] = []
        try:
            data = json.loads(res.stdout or b"[]")
        except json.JSONDecodeError:
            return []
        for rec in data:
            kind = rec.get("RuleID", "secret")
            file = rec.get("File")
            line_no = rec.get("StartLine", 0)
            out.append(
                Finding(
                    detector=f"secret:gitleaks:{kind}",
                    layer="static_analysis",
                    issue_code="CWE-798",
                    severity="medium",
                    confidence=0.65,
                    evidence={
                        "file": file,
                        "line": line_no,
                        "rule_id": kind,
                        "evidence_key": f"gitleaks:{kind}:{file}:{line_no}",
                    },
                    artifact_ref=target.artifact_ref,
                    server_id=target.server_id,
                )
            )
        return out

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple] = set()
        out: list[Finding] = []
        for f in findings:
            key = (
                f.evidence.get("file"),
                f.evidence.get("line"),
                f.evidence.get("detector_name") or f.evidence.get("rule_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out
