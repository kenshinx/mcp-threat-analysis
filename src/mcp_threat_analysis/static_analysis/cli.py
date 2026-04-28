"""CLI: scan a single target locally."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from uuid import UUID, uuid4

from ..common.models import ScanTarget
from .orchestrator import StaticAnalysisConfig, StaticAnalysisOrchestrator


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser("mta-l2")
    p.add_argument("artifact", help="Local archive / directory / URL")
    p.add_argument("--server-id", default=None)
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


async def _amain(ns: argparse.Namespace) -> int:
    target = ScanTarget(
        server_id=UUID(ns.server_id) if ns.server_id else uuid4(),
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
