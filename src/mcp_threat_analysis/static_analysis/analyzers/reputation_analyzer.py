"""Lightweight dependency reputation: download counts, account age."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ..models import StaticAnalysisContext
from .base import Analyzer

log = get_logger(__name__)

_NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week/{name}"
_NPM_INFO = "https://registry.npmjs.org/{name}"


class ReputationAnalyzer(Analyzer):
    name = "reputation"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        if not context.sca_deps:
            return []
        npm_deps = [d for d in context.sca_deps if d.get("registry") == "npm"]
        if not npm_deps:
            return []
        async with httpx.AsyncClient(timeout=10.0) as client:
            return await self._check_npm(client, npm_deps, target)

    async def _check_npm(
        self,
        client: httpx.AsyncClient,
        deps: list[dict],
        target: ScanTarget,
    ) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        sem = asyncio.Semaphore(8)

        async def check(dep: dict) -> Finding | None:
            name = dep.get("name")
            if not name or name in seen:
                return None
            seen.add(name)
            async with sem:
                try:
                    dl_resp, info_resp = await asyncio.gather(
                        client.get(_NPM_DOWNLOADS.format(name=name)),
                        client.get(_NPM_INFO.format(name=name)),
                    )
                except httpx.HTTPError:
                    return None
            if dl_resp.status_code != 200 or info_resp.status_code != 200:
                return None
            downloads = (dl_resp.json() or {}).get("downloads", 0)
            info = info_resp.json() or {}
            time = info.get("time") or {}
            created = time.get("created")
            age_days = _days_since(created)
            severity = None
            confidence = 0.6
            reasons: list[str] = []
            if downloads is not None and downloads < 50:
                severity = "medium"
                reasons.append(f"weekly_downloads={downloads}")
            if age_days is not None and age_days < 30:
                severity = "high" if severity == "medium" else "medium"
                reasons.append(f"package_age_days={age_days}")
            if not severity:
                return None
            return Finding(
                detector="reputation:low-rep-npm",
                layer="static_analysis",
                issue_code=None,
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,
                evidence={
                    "package": name,
                    "version": dep.get("version"),
                    "weekly_downloads": downloads,
                    "age_days": age_days,
                    "reasons": reasons,
                    "evidence_key": f"reputation:npm:{name}",
                },
                artifact_ref=target.artifact_ref,
                server_id=target.server_id,
            )

        results = await asyncio.gather(*(check(d) for d in deps))
        for r in results:
            if r is not None:
                out.append(r)
        return out


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days
