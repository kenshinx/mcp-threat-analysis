"""Tests for common.models — Finding.evidence_key, ScanTarget.artifact_ref, WorkDir.find."""
from __future__ import annotations

import tempfile
from pathlib import Path
from uuid import uuid4

from mcp_threat_analysis.common.models import Finding, ScanTarget, WorkDir


# --- Finding.evidence_key ---

def test_evidence_key_from_explicit_key():
    f = Finding(
        detector="test", layer="static_analysis", severity="high", confidence=0.9,
        evidence={"evidence_key": "custom:123"}, artifact_ref="ref",
    )
    assert f.evidence_key() == "custom:123"


def test_evidence_key_fallback():
    f = Finding(
        detector="test", layer="static_analysis", severity="high", confidence=0.9,
        evidence={"file": "a.py", "line": "42", "tool_name": "read"}, artifact_ref="ref",
    )
    assert f.evidence_key() == "a.py:42:read"


def test_evidence_key_empty_evidence():
    f = Finding(
        detector="test", layer="static_analysis", severity="high", confidence=0.9,
        evidence={}, artifact_ref="ref",
    )
    assert f.evidence_key() == "::"


def test_evidence_key_none_evidence():
    f = Finding(
        detector="test", layer="static_analysis", severity="high", confidence=0.9,
        evidence=None, artifact_ref="ref",
    )
    assert f.evidence_key() == "::"


# --- ScanTarget.artifact_ref ---

def test_artifact_ref_format():
    sid = uuid4()
    t = ScanTarget(
        server_id=sid, version="1.2.3", artifact_type="npm_tarball",
        artifact_path="/tmp/x.tgz", primary_lang="typescript",
    )
    assert t.artifact_ref == f"{sid}:1.2.3"


# --- WorkDir.find ---

def test_find_matching_files():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "package.json").write_text("{}")
        (root / "index.ts").write_text("")
        (root / "sub").mkdir()
        (root / "sub" / "package.json").write_text("{}")

        wd = WorkDir(root_path=root, primary_lang="ts", lang_files={})
        found = wd.find(["package.json"])
        assert len(found) == 2
        names = {p.name for p in found}
        assert names == {"package.json"}


def test_find_no_match():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "readme.md").write_text("hi")
        wd = WorkDir(root_path=root, primary_lang="ts", lang_files={})
        assert wd.find(["package.json"]) == []


def test_find_ignores_directories():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "src").mkdir()
        wd = WorkDir(root_path=root, primary_lang="ts", lang_files={})
        assert wd.find(["src"]) == []
