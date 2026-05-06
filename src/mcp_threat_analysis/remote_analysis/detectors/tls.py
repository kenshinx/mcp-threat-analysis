"""TLS-cert hygiene detectors."""
from __future__ import annotations

from ..models import ProbeResult, RemoteFinding


def detect_tls(result: ProbeResult) -> list[RemoteFinding]:
    if result.tls is None:
        return []
    out: list[RemoteFinding] = []
    tls = result.tls
    base_evidence = {
        "subject": tls.subject,
        "issuer": tls.issuer,
        "not_after": tls.not_after,
        "sha256": tls.sha256,
        "san": tls.san,
        "endpoint": result.request.endpoint,
    }

    if tls.self_signed:
        out.append(RemoteFinding(
            detector="remote:tls-self-signed",
            severity="high",
            confidence=0.95,
            evidence={
                **base_evidence,
                "evidence_key": f"tls-self-signed:{tls.sha256 or result.request.endpoint}",
            },
            issue_code="R001",
        ))

    days = tls.days_until_expiry
    if days is not None:
        if days <= 7:
            out.append(RemoteFinding(
                detector="remote:tls-near-expiry",
                severity="high",
                confidence=0.99,
                evidence={
                    **base_evidence,
                    "days_until_expiry": days,
                    "evidence_key": f"tls-expiry:{tls.sha256 or result.request.endpoint}",
                },
                issue_code="R002",
            ))
        elif days <= 30:
            out.append(RemoteFinding(
                detector="remote:tls-near-expiry",
                severity="medium",
                confidence=0.95,
                evidence={
                    **base_evidence,
                    "days_until_expiry": days,
                    "evidence_key": f"tls-expiry:{tls.sha256 or result.request.endpoint}",
                },
                issue_code="R002",
            ))
    return out
