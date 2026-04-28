"""CodeQL wrapper. Builds a database, runs query suite, parses SARIF.

Disabled by default unless `codeql` binary is on PATH and the project
language is supported. Failures are non-fatal — orchestrator skips on
build/run errors and emits an ops metric.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from ...common.config import get_settings
from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ...common.subprocess_runner import AnalyzerTimeout, run
from ..models import StaticAnalysisContext
from .base import Analyzer

log = get_logger(__name__)

_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
    "go": "go",
}

_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"


class CodeQLAnalyzer(Analyzer):
    name = "codeql"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        if not shutil.which(get_settings().codeql_bin):
            log.info("codeql.skip", reason="binary not on PATH")
            return []
        ql_lang = _LANG_MAP.get(target.primary_lang)
        if ql_lang is None:
            return []

        tmp = Path(tempfile.mkdtemp(prefix="codeql-db-"))
        db = tmp / "db"
        sarif = tmp / "results.sarif"
        try:
            create = await run(
                [
                    get_settings().codeql_bin,
                    "database",
                    "create",
                    str(db),
                    f"--language={ql_lang}",
                    f"--source-root={workdir.root_path}",
                    "--overwrite",
                ],
                timeout_s=get_settings().codeql_timeout_s,
            )
            if create.returncode != 0:
                log.warning("codeql.db_failed", rc=create.returncode)
                return []
            analyze = await run(
                [
                    get_settings().codeql_bin,
                    "database",
                    "analyze",
                    str(db),
                    "--format=sarif-latest",
                    f"--output={sarif}",
                    _SUITE,
                ],
                timeout_s=get_settings().codeql_timeout_s,
            )
            if analyze.returncode != 0 or not sarif.exists():
                log.warning("codeql.analyze_failed", rc=analyze.returncode)
                return []
            return self._parse_sarif(sarif.read_text(), target)
        except AnalyzerTimeout:
            log.warning("codeql.timeout")
            return []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _parse_sarif(self, sarif_text: str, target: ScanTarget) -> list[Finding]:
        try:
            data = json.loads(sarif_text)
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for run_obj in data.get("runs", []):
            for r in run_obj.get("results", []):
                rule_id = r.get("ruleId") or "codeql:unknown"
                severity = _level_to_severity(r.get("level", "warning"))
                loc = (r.get("locations") or [{}])[0]
                pl = loc.get("physicalLocation", {})
                file = (pl.get("artifactLocation") or {}).get("uri")
                line = (pl.get("region") or {}).get("startLine")
                out.append(
                    Finding(
                        detector=f"codeql:{rule_id}",
                        layer="static_analysis",
                        issue_code=_rule_to_cwe(rule_id),
                        severity=severity,
                        confidence=0.85,
                        evidence={
                            "file": file,
                            "line": line,
                            "rule_id": rule_id,
                            "message": (r.get("message") or {}).get("text"),
                            "evidence_key": f"{file}:{line}:{rule_id}",
                        },
                        artifact_ref=target.artifact_ref,
                        server_id=target.server_id,
                    )
                )
        return out


def _level_to_severity(level: str) -> str:
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "low")


def _rule_to_cwe(rule_id: str) -> str | None:
    rid = rule_id.lower()
    if "command-injection" in rid:
        return "CWE-78"
    if "path-injection" in rid or "path-traversal" in rid:
        return "CWE-22"
    if "ssrf" in rid:
        return "CWE-918"
    if "sql-injection" in rid:
        return "CWE-89"
    return None
