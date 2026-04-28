"""risk_scoring: weight tables — code defaults plus optional YAML override."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..common.config import get_settings

DEFAULT_VERSION = "default-1"

DEFAULT_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.1,
}

DEFAULT_DETECTOR_CLASS_WEIGHTS: dict[str, float] = {
    "static:semgrep": 1.0,
    "static:codeql": 1.2,
    "static:secret": 1.5,
    "static:sca": 0.8,
    "static:manifest": 1.0,
    "static:reputation": 0.6,
    "static:obfuscation": 1.2,
    "semantic:char": 1.5,
    "semantic:tpa-rule": 1.2,
    "semantic:tpa-llm": 1.5,
    "semantic:shadowing": 1.0,
    "semantic:schema-code": 2.0,
    "semantic:toxic-flow": 1.5,
    "semantic:untrusted": 0.8,
    "runtime:version-diff": 2.0,
    "runtime:remote-targeted": 3.0,
    "runtime:namespace": 2.0,
    "runtime:commit-anomaly": 1.5,
    "network:dynamic-egress": 2.5,
    "network:dynamic-fs": 2.0,
    "network:protocol-anomaly": 1.5,
}


@dataclass(slots=True)
class Weights:
    severity: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_WEIGHTS))
    detector_class: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_DETECTOR_CLASS_WEIGHTS))
    version: str = DEFAULT_VERSION

    def class_weight(self, detector: str) -> float:
        cls = detector_to_class(detector)
        return self.detector_class.get(cls, 1.0)


def detector_to_class(detector: str) -> str:
    """Map a detector string to its weight-class key.

    Examples:
      semgrep:foo                  → static:semgrep
      secret:trufflehog:aws        → static:secret
      sca:osv:GHSA-xxxx            → static:sca
      reputation:low-rep-npm       → static:reputation
      manifest:install-hook-...    → static:manifest
      obfuscation:composite        → static:obfuscation
      codeql:py/path-injection     → static:codeql
      char:hidden-unicode          → semantic:char
      tpa-rule:tool-poisoning-...  → semantic:tpa-rule
      tpa-llm                      → semantic:tpa-llm
      shadow:name-collision        → semantic:shadowing
      llm:schema-code-...          → semantic:schema-code
      toxic-flow:...               → semantic:toxic-flow
      untrusted-content:...        → semantic:untrusted
    """
    head = detector.split(":", 1)[0]
    if head in {"semgrep", "codeql", "secret", "sca", "manifest", "obfuscation", "reputation"}:
        return f"static:{head}"
    if head in {"char"}:
        return "semantic:char"
    if head == "tpa-rule":
        return "semantic:tpa-rule"
    if head == "tpa-llm":
        return "semantic:tpa-llm"
    if head == "shadow":
        return "semantic:shadowing"
    if head == "llm":
        return "semantic:schema-code"
    if head == "toxic-flow":
        return "semantic:toxic-flow"
    if head == "untrusted-content":
        return "semantic:untrusted"
    if head == "version-diff":
        return "runtime:version-diff"
    if head == "remote":
        return "runtime:remote-targeted"
    if head == "ns":
        return "runtime:namespace"
    if head == "git":
        return "runtime:commit-anomaly"
    if head == "dynamic-egress":
        return "network:dynamic-egress"
    if head == "dynamic-fs":
        return "network:dynamic-fs"
    if head == "protocol":
        return "network:protocol-anomaly"
    return "unknown"


def load_weights(path: Path | None = None) -> Weights:
    p = path or (
        Path(get_settings().weights_yaml_path) if get_settings().weights_yaml_path else None
    )
    if p is None or not p.exists():
        return Weights()
    data: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    w = Weights()
    if "severity" in data:
        w.severity = {**w.severity, **data["severity"]}
    if "detector_class" in data:
        w.detector_class = {**w.detector_class, **data["detector_class"]}
    w.version = str(data.get("version", DEFAULT_VERSION))
    return w
