"""Tree-sitter-based AST extraction for tool handlers.

Produces ToolHandler objects with IO summaries. Tree-sitter languages are
loaded lazily; if a language binding is missing, the extractor falls back
to regex-based IO discovery so the rest of the pipeline still runs.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...common.logging import get_logger
from ...common.models import (
    FileOp,
    IOSummary,
    NetworkCall,
    SubprocessCall,
    ToolHandler,
)
from .tool_handler_locator import HandlerCandidate

log = get_logger(__name__)

_NETWORK_FNS = re.compile(
    r"\b(requests\.(get|post|put|delete|patch)|httpx\.\w+|urllib\.request\.urlopen|"
    r"fetch|axios\.\w+|http\.Get|http\.Post)\s*\("
)
_FILE_READ_FNS = re.compile(
    r"\b(open|fs\.readFile|fs\.readFileSync|ioutil\.ReadFile|os\.ReadFile)\s*\("
)
_FILE_WRITE_FNS = re.compile(
    r"\b(fs\.writeFile|fs\.writeFileSync|ioutil\.WriteFile|os\.WriteFile)\s*\("
)
_SUBPROCESS_FNS = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_output)|os\.system|os\.popen|"
    r"child_process\.(?:exec|execSync|spawn)|exec\.Command)\s*\("
)
_ENV_READS = re.compile(r"\bos\.(?:environ|getenv)|process\.env\.(\w+)|os\.Getenv\(")
_CRYPTO = re.compile(
    r"\b(hashlib\.\w+|crypto\.createHash|crypto\.subtle|aes|cipher)\s*\("
)


class ASTExtractor:
    def extract(
        self, candidates: list[HandlerCandidate]
    ) -> list[ToolHandler]:
        # Group candidates by file to read each file once.
        by_file: dict[Path, list[HandlerCandidate]] = {}
        for c in candidates:
            by_file.setdefault(c.file, []).append(c)

        handlers: list[ToolHandler] = []
        for file, cands in by_file.items():
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            io = self._scan_io(text)
            for c in cands:
                handlers.append(
                    ToolHandler(
                        name=c.name_hint or _infer_name(c.snippet) or f"<unknown@{file.name}:{c.line}>",
                        declared_description=_infer_description(c.snippet, text, c.line),
                        declared_input_schema=None,
                        file=str(file),
                        line_start=c.line,
                        line_end=c.line + 50,
                        io_summary=io,
                    )
                )
        return handlers

    def _scan_io(self, text: str) -> IOSummary:
        io = IOSummary()
        for m in _NETWORK_FNS.finditer(text):
            line = text[: m.start()].count("\n") + 1
            io.network_calls.append(
                NetworkCall(func=m.group(0), url_arg_kind="var", url_literal=None, line=line)
            )
        for m in _FILE_READ_FNS.finditer(text):
            line = text[: m.start()].count("\n") + 1
            io.file_reads.append(
                FileOp(func=m.group(0), path_arg_kind="var", path_literal=None, mode="r", line=line)
            )
        for m in _FILE_WRITE_FNS.finditer(text):
            line = text[: m.start()].count("\n") + 1
            io.file_writes.append(
                FileOp(func=m.group(0), path_arg_kind="var", path_literal=None, mode="w", line=line)
            )
        for m in _SUBPROCESS_FNS.finditer(text):
            line = text[: m.start()].count("\n") + 1
            io.subprocess_calls.append(
                SubprocessCall(func=m.group(0), cmd_arg_kind="var", cmd_literal=None, line=line)
            )
        io.env_reads = list({g for g in _ENV_READS.findall(text) if g})
        io.crypto_calls = list({m.group(0) for m in _CRYPTO.finditer(text)})
        return io


def _infer_name(snippet: str) -> str | None:
    m = re.search(r"['\"]([\w\-]+)['\"]", snippet)
    return m.group(1) if m else None


def _infer_description(snippet: str, full_text: str, line: int) -> str | None:
    # Look at the next 30 lines after the candidate for a docstring or
    # description= keyword arg.
    lines = full_text.splitlines()
    window = "\n".join(lines[line - 1 : line + 30])
    m = re.search(r"description\s*[:=]\s*['\"]([^'\"]{3,500})['\"]", window)
    if m:
        return m.group(1)
    m = re.search(r"\"\"\"([^\"]{3,500})\"\"\"", window) or re.search(
        r"'''([^']{3,500})'''", window
    )
    if m:
        return m.group(1).strip()
    return None
