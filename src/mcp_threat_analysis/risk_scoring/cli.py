"""CLI: run aggregator once, or start the polling ingestor."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from uuid import UUID

from ..common.db import session_scope
from .aggregator import Aggregator
from .ingestor import Ingestor


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser("mta-l6")
    sub = p.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("aggregate")
    one.add_argument("server_id")
    sub.add_parser("ingest")
    return p.parse_args(argv)


async def _aggregate_one(server_id: str) -> int:
    aggregator = Aggregator()
    async with session_scope() as session:
        result = await aggregator.aggregate(session, UUID(server_id))
    json.dump(
        {
            "server_id": str(result.server_id),
            "score": result.score,
            "base_score": result.base_score,
            "boost": result.boost,
            "boost_rules": result.boost_rules,
            "popularity": result.popularity,
            "finding_count": result.finding_count,
            "weights_version": result.weights_version,
            "top_findings": result.top_findings,
        },
        sys.stdout,
        indent=2,
        default=str,
    )
    print()
    return 0


async def _ingest_loop() -> int:
    ingestor = Ingestor()
    await ingestor.run_forever()
    return 0


def main() -> None:
    ns = _parse(sys.argv[1:])
    if ns.cmd == "aggregate":
        sys.exit(asyncio.run(_aggregate_one(ns.server_id)))
    elif ns.cmd == "ingest":
        sys.exit(asyncio.run(_ingest_loop()))


if __name__ == "__main__":
    main()
