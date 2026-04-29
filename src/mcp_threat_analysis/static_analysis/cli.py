"""CLI: scan a single target locally."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path
from uuid import UUID, uuid4

from ..common.db import session_scope
from ..common.models import ScanTarget
from ..common.persistence import ensure_server
from .orchestrator import StaticAnalysisConfig, StaticAnalysisOrchestrator


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser("mta-static")
    p.add_argument("artifact", help="Local archive / directory / URL")
    p.add_argument("--server-id", default=None)
    p.add_argument(
        "--canonical-name",
        default=None,
        help="Stable server name; defaults to artifact basename. "
        "Re-runs with the same name reuse the same server_id.",
    )
    p.add_argument("--version", default="0.0.0")
    p.add_argument("--lang", default="python")
    p.add_argument(
        "--artifact-type",
        default="github_archive",
        choices=["npm_tarball", "pypi_wheel", "docker_image", "github_archive"],
    )
    p.add_argument("--no-codeql", action="store_true")
    p.add_argument("--no-reputation", action="store_true")
    p.add_argument("--no-persist", action="store_true")
    return p.parse_args(argv)


def _derive_canonical_name(artifact: str) -> str:
    base = Path(artifact).name
    for ext in (".tgz", ".tar.gz", ".zip", ".whl"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base or artifact


async def _amain(ns: argparse.Namespace) -> int:
    canonical_name = ns.canonical_name or _derive_canonical_name(ns.artifact)
    server_id_hint = UUID(ns.server_id) if ns.server_id else None
    if ns.no_persist:
        server_id = server_id_hint or uuid4()
    else:
        async with session_scope() as session:
            server_id = await ensure_server(
                session,
                canonical_name=canonical_name,
                server_id=server_id_hint,
                primary_lang=ns.lang,
            )
    target = ScanTarget(
        server_id=server_id,
        version=ns.version,
        artifact_type=ns.artifact_type,
        artifact_path=ns.artifact,
        primary_lang=ns.lang,
    )
    orch = StaticAnalysisOrchestrator(
        config=StaticAnalysisConfig(
            enable_codeql=not ns.no_codeql,
            enable_reputation=not ns.no_reputation,
        )
    )
    result = await orch.run(target, persist=not ns.no_persist)
    out = {
        "server_id": str(target.server_id),
        "version": target.version,
        "finding_count": len(result.findings),
        "findings": [asdict(f) for f in result.findings],
        "obfuscation_score": result.context.obfuscation_score,
    }
    json.dump(out, sys.stdout, default=str, indent=2)
    print()
    return 0


def main() -> None:
    ns = _parse_args(sys.argv[1:])
    sys.exit(asyncio.run(_amain(ns)))


if __name__ == "__main__":
    main()
