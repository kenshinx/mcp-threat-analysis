"""CLI: scan one (server_id, version) for semantic_analysis."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from uuid import UUID

from .orchestrator import SemanticAnalysisConfig, SemanticAnalysisOrchestrator


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser("mta-l3")
    p.add_argument("--server-id", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--no-persist", action="store_true")
    return p.parse_args(argv)


async def _amain(ns: argparse.Namespace) -> int:
    orch = SemanticAnalysisOrchestrator(config=SemanticAnalysisConfig(enable_llm=not ns.no_llm))
    result = await orch.run(
        UUID(ns.server_id),
        ns.version,
        persist=not ns.no_persist,
    )
    json.dump(
        {
            "server_id": ns.server_id,
            "version": ns.version,
            "finding_count": len(result.findings),
            "findings": [asdict(f) for f in result.findings],
        },
        sys.stdout,
        default=str,
        indent=2,
    )
    print()
    return 0


def main() -> None:
    ns = _parse_args(sys.argv[1:])
    sys.exit(asyncio.run(_amain(ns)))


if __name__ == "__main__":
    main()
