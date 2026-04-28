"""Find MCP tool handler entry points across supported languages.

Pure regex-based first pass; tree-sitter parser refines results in
ASTExtractor. The locator returns coarse (file, line, name) candidates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_PY_PATTERNS = [
    re.compile(r"@(?:mcp|server)\.tool\s*\(", re.M),
    re.compile(r"FastMCP\s*\(", re.M),
]
_TS_JS_PATTERNS = [
    re.compile(r"\.setRequestHandler\s*\(\s*['\"]tools/call['\"]", re.M),
    re.compile(r"\.tool\s*\(\s*['\"]([\w\-]+)['\"]"),
    re.compile(r"new\s+Server\s*\(", re.M),
]
_GO_PATTERNS = [
    re.compile(r"mcp\.RegisterTool\s*\("),
    re.compile(r"server\.AddTool\s*\("),
]


@dataclass(slots=True)
class HandlerCandidate:
    file: Path
    line: int
    snippet: str
    lang: str
    name_hint: str | None = None


class ToolHandlerLocator:
    def locate(self, lang_files: dict[str, list[Path]]) -> list[HandlerCandidate]:
        out: list[HandlerCandidate] = []
        for lang, files in lang_files.items():
            patterns = self._patterns_for(lang)
            if not patterns:
                continue
            for f in files:
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for pat in patterns:
                    for m in pat.finditer(text):
                        line = text[: m.start()].count("\n") + 1
                        out.append(
                            HandlerCandidate(
                                file=f,
                                line=line,
                                snippet=text[m.start() : m.start() + 200],
                                lang=lang,
                                name_hint=m.group(1) if m.groups() else None,
                            )
                        )
        return out

    def _patterns_for(self, lang: str) -> list[re.Pattern[str]]:
        if lang == "python":
            return _PY_PATTERNS
        if lang in ("typescript", "javascript"):
            return _TS_JS_PATTERNS
        if lang == "go":
            return _GO_PATTERNS
        return []
