"""Pure-function detector tests — no DB, no network."""
from __future__ import annotations

from datetime import UTC, datetime

from mcp_threat_analysis.remote_analysis.detectors import (
    detect_auth_missing,
    detect_protocol_version,
    detect_tls,
)
from mcp_threat_analysis.remote_analysis.models import ProbeRequest, ProbeResult, TLSInfo


def _ok_result(**overrides) -> ProbeResult:
    base = dict(
        request=ProbeRequest(endpoint="https://mcp.example.com/", transport="streamable_http"),
        ok=True,
        probed_at=datetime.now(UTC),
        latency_ms=100,
        protocol_ver="2025-03-26",
        tools=[{"name": "x", "description": "d"}],
    )
    base.update(overrides)
    return ProbeResult(**base)


def test_tls_self_signed_high():
    r = _ok_result(tls=TLSInfo(self_signed=True, days_until_expiry=400, sha256="abc"))
    findings = detect_tls(r)
    assert any(f.detector == "remote:tls-self-signed" and f.severity == "high" for f in findings)


def test_tls_near_expiry_severities():
    r1 = _ok_result(tls=TLSInfo(days_until_expiry=5, sha256="a"))
    r2 = _ok_result(tls=TLSInfo(days_until_expiry=20, sha256="b"))
    r3 = _ok_result(tls=TLSInfo(days_until_expiry=200, sha256="c"))
    f1 = detect_tls(r1); f2 = detect_tls(r2); f3 = detect_tls(r3)
    assert any(f.severity == "high" for f in f1)
    assert any(f.severity == "medium" for f in f2)
    assert all(f.detector != "remote:tls-near-expiry" for f in f3)


def test_auth_missing_skips_loopback():
    r = _ok_result(
        request=ProbeRequest(endpoint="http://localhost:8000/", transport="streamable_http"),
        auth_kind="none",
    )
    assert detect_auth_missing(r) == []


def test_auth_missing_fires_on_internet():
    r = _ok_result(auth_kind="none")
    findings = detect_auth_missing(r)
    assert findings and findings[0].detector == "remote:auth-missing"


def test_auth_missing_quiet_when_authenticated():
    r = _ok_result(auth_kind="oauth")
    assert detect_auth_missing(r) == []


def test_protocol_version_known_quiet():
    r = _ok_result(protocol_ver="2025-03-26")
    assert detect_protocol_version(r) == []


def test_protocol_version_mismatch_info():
    r = _ok_result(protocol_ver="9999-01-01")
    findings = detect_protocol_version(r)
    assert findings and findings[0].severity == "info"
    assert findings[0].evidence["reported"] == "9999-01-01"
