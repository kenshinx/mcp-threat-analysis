"""mta-remote — CLI entry point for the remote_analysis layer.

Subcommands (P1):
  mta-remote scan <endpoint> [--transport streamable_http] [--canonical-name NAME]
                             [--header KEY=VAL]... [--timeout 15]

P2 will add: register / watch / diff / import.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from urllib.parse import urlparse

from .models import ProbeRequest
from .orchestrator import scan


def _parse_headers(items: list[str]) -> dict[str, str]:
    headers = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--header expects KEY=VAL, got: {item}")
        k, v = item.split("=", 1)
        headers[k.strip()] = v.strip()
    return headers


def _default_canonical_name(endpoint: str) -> str:
    u = urlparse(endpoint)
    host = u.hostname or "remote"
    path = (u.path or "").strip("/").replace("/", "_") or "root"
    return f"remote_{host.replace('.', '_')}_{path}"[:120]


def _print_outcome(outcome) -> None:
    r = outcome.result
    summary = {
        "server_id": str(outcome.server_id),
        "canonical_name": outcome.canonical_name,
        "observation_id": str(outcome.observation_id),
        "ok": r.ok,
        "latency_ms": r.latency_ms,
        "protocol_ver": r.protocol_ver,
        "tools_count": len(r.tools),
        "auth_kind": r.auth_kind,
        "error": r.error,
        "findings": [
            {
                "detector": f.detector,
                "severity": f.severity,
                "confidence": f.confidence,
                "issue_code": f.issue_code,
                "evidence_key": f.evidence.get("evidence_key"),
            }
            for f in outcome.findings
        ],
    }
    json.dump(summary, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


async def _run_scan(args: argparse.Namespace) -> int:
    req = ProbeRequest(
        endpoint=args.endpoint,
        transport=args.transport,
        headers=_parse_headers(args.header),
        timeout_s=args.timeout,
    )
    name = args.canonical_name or _default_canonical_name(args.endpoint)
    outcome = await scan(req, canonical_name=name)
    _print_outcome(outcome)
    return 0 if outcome.result.ok else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mta-remote", description="Probe live MCP servers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="One-shot probe + detect + persist.")
    scan_p.add_argument("endpoint", help="MCP endpoint URL (https://...).")
    scan_p.add_argument("--transport", default="streamable_http",
                        choices=["streamable_http"])
    scan_p.add_argument("--canonical-name", default=None,
                        help="Server canonical_name (default: derived from URL).")
    scan_p.add_argument("--header", action="append", default=[],
                        help="Repeatable. e.g. --header Authorization='Bearer ...'.")
    scan_p.add_argument("--timeout", type=float, default=15.0)

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return asyncio.run(_run_scan(args))
    parser.error("unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
