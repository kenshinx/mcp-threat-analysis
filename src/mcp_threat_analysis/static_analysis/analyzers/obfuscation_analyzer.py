"""Heuristic obfuscation detection.

Composite score in [0, 1]:
  0.4 * high_entropy_density
+ 0.3 * minified_only_ratio
+ 0.3 * suspicious_eval_pattern_ratio
"""
from __future__ import annotations

import re
from pathlib import Path

from ...common.logging import get_logger
from ...common.models import Finding, ScanTarget, WorkDir
from ..extractors.string_extractor import shannon_entropy
from ..models import StaticAnalysisContext
from ..target_loader import is_text_file
from .base import Analyzer

log = get_logger(__name__)

_EVAL_PATTERNS = [
    re.compile(r"\beval\s*\(\s*atob\s*\("),
    re.compile(r"\bexec\s*\(\s*base64\.b64decode\s*\("),
    re.compile(r"\bFunction\s*\(\s*['\"][\w+/=]{40,}['\"]"),
    re.compile(r"\bvm\.runIn\w*Context\s*\("),
]


class ObfuscationAnalyzer(Analyzer):
    name = "obfuscation"

    async def analyze(
        self, workdir: WorkDir, context: StaticAnalysisContext, target: ScanTarget
    ) -> list[Finding]:
        score, evidence = self._compute_score(workdir.root_path)
        context.obfuscation_score = score
        if score < 0.3:
            return []
        sev = "high" if score >= 0.6 else "medium"
        return [
            Finding(
                detector="obfuscation:composite",
                layer="static_analysis",
                issue_code=None,
                severity=sev,  # type: ignore[arg-type]
                confidence=min(0.95, 0.5 + score / 2),
                evidence={
                    "obfuscation_score": score,
                    "components": evidence,
                    "evidence_key": "obfuscation:composite",
                },
                artifact_ref=target.artifact_ref,
                server_id=target.server_id,
            )
        ]

    def _compute_score(self, root: Path) -> tuple[float, dict]:
        files: list[Path] = [p for p in root.rglob("*") if p.is_file() and is_text_file(p)]
        if not files:
            return 0.0, {}
        high_entropy = 0
        total_strings = 0
        minified_files = 0
        eval_hits = 0
        sampled = files[:1000]
        for p in sampled:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines() or [""]
            longest = max(len(l) for l in lines)
            if longest > 5000 and len(lines) < 10:
                minified_files += 1
            for m in re.finditer(r'"((?:[^"\\]|\\.){50,})"', text):
                total_strings += 1
                if shannon_entropy(m.group(1)) >= 4.5:
                    high_entropy += 1
            for pat in _EVAL_PATTERNS:
                eval_hits += len(pat.findall(text))
        density = high_entropy / max(1, total_strings)
        minified_ratio = minified_files / len(sampled)
        eval_ratio = min(1.0, eval_hits / max(1, len(sampled)))
        score = 0.4 * density + 0.3 * minified_ratio + 0.3 * eval_ratio
        return round(score, 3), {
            "high_entropy_density": round(density, 3),
            "minified_ratio": round(minified_ratio, 3),
            "eval_pattern_density": round(eval_ratio, 3),
            "files_sampled": len(sampled),
        }
