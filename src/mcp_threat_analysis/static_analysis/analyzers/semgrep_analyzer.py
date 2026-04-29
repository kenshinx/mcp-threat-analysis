"""Run Semgrep with self + translated_from_cisco rule packs."""
from __future__ import annotations

import json
from pathlib import Path

from ...common.config import get_settings
from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ...common.subprocess_runner import AnalyzerTimeout, run
from ..models import StaticAnalysisContext
from .base import Analyzer

log = get_logger(__name__)

_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class SemgrepAnalyzer(Analyzer):
    name = "semgrep"

    def __init__(self, rules_root: Path | None = None) -> None:
        self.rules_root = rules_root or Path(__file__).resolve().parents[1] / "rules" / "semgrep"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        cfg_paths = [str(p) for p in self._select_rules(target.primary_lang)]
        if not cfg_paths:
            return []
        argv = [
            get_settings().semgrep_bin,
            "--json",
            "--quiet",
            "--metrics=off",
            "--timeout=0",
        ]
        for c in cfg_paths:
            argv.extend(["--config", c])
        argv.append(str(workdir.root_path))

        try:
            res = await run(argv, timeout_s=get_settings().semgrep_timeout_s)
        except AnalyzerTimeout:
            log.warning("semgrep.timeout", server=str(target.server_id))
            return []
        if res.returncode not in (0, 1):
            stdout_head = res.stdout[:2000].decode("utf-8", errors="replace")
            errors_summary: list[str] = []
            try:
                payload = json.loads(res.stdout or b"{}")
                for err in (payload.get("errors") or [])[:10]:
                    errors_summary.append(
                        f"{err.get('type')}: {err.get('message')} "
                        f"(path={err.get('path') or err.get('spans')})"
                    )
            except json.JSONDecodeError:
                pass
            log.warning(
                "semgrep.bad_rc",
                rc=res.returncode,
                stderr=res.stderr[:500].decode("utf-8", errors="replace"),
                stdout_head=stdout_head,
                semgrep_errors=errors_summary,
            )
            return []
        try:
            data = json.loads(res.stdout or b"{}")
        except json.JSONDecodeError:
            log.warning("semgrep.bad_json")
            return []

        out: list[Finding] = []
        for hit in data.get("results", []):
            out.append(self._to_finding(hit, target, context))
        return out

    def _select_rules(self, primary_lang: str) -> list[Path]:
        out: list[Path] = []
        if not self.rules_root.exists():
            return out
        for sub in ("self/code", "self/text", "self/manifest", "translated_from_cisco"):
            p = self.rules_root / sub
            if not p.exists():
                continue
            # Semgrep exits rc=2 if a config dir contains zero rule files.
            if not any(p.rglob("*.yaml")) and not any(p.rglob("*.yml")):
                continue
            out.append(p)
        return out

    def _to_finding(
        self, hit: dict, target: ScanTarget, context: StaticAnalysisContext
    ) -> Finding:
        check_id = hit.get("check_id", "semgrep:unknown")
        rule_short = check_id.split(".")[-1]
        meta = (hit.get("extra") or {}).get("metadata") or {}
        sev_raw = (hit.get("extra") or {}).get("severity") or "INFO"
        severity = _SEVERITY_MAP.get(sev_raw, "low")
        # Allow rule to override severity via metadata.severity_override.
        severity = meta.get("severity_override", severity)
        return Finding(
            detector=f"semgrep:{rule_short}",
            layer="static_analysis",
            issue_code=meta.get("issue_code"),
            severity=severity,
            confidence=float(meta.get("confidence", 0.7)),
            evidence={
                "file": hit.get("path"),
                "line": ((hit.get("start") or {}).get("line")),
                "snippet": ((hit.get("extra") or {}).get("lines"))[:1000]
                if (hit.get("extra") or {}).get("lines")
                else None,
                "rule_id": check_id,
                "tool_name": _resolve_tool_name(
                    hit.get("path"),
                    (hit.get("start") or {}).get("line"),
                    context,
                ),
                "evidence_key": f"{hit.get('path')}:{(hit.get('start') or {}).get('line')}:{rule_short}",
            },
            artifact_ref=target.artifact_ref,
            server_id=target.server_id,
        )


def _resolve_tool_name(file: str | None, line: int | None, ctx: StaticAnalysisContext) -> str | None:
    if not file or line is None:
        return None
    for h in ctx.tool_handlers:
        if h.file == file and h.line_start <= line <= h.line_end:
            return h.name
    return None
