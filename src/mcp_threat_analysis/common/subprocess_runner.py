"""Thin async subprocess wrapper used by all external tool analyzers."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .logging import get_logger

log = get_logger(__name__)


class AnalyzerTimeout(Exception):
    pass


@dataclass(slots=True)
class ProcResult:
    returncode: int
    stdout: bytes
    stderr: bytes


async def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout_s: int,
    env: dict[str, str] | None = None,
) -> ProcResult:
    log.info("subprocess.start", argv=argv, cwd=str(cwd) if cwd else None)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError as e:
        proc.kill()
        await proc.wait()
        log.warning("subprocess.timeout", argv=argv, timeout_s=timeout_s)
        raise AnalyzerTimeout(f"{argv[0]} timed out after {timeout_s}s") from e
    log.info("subprocess.done", argv=argv, rc=proc.returncode)
    return ProcResult(returncode=proc.returncode or 0, stdout=stdout, stderr=stderr)
