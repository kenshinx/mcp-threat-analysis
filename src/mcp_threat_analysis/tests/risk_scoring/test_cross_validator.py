from mcp_threat_analysis.risk_scoring.cross_validator import CrossValidator


def test_postmark_pattern_triggers():
    cv = CrossValidator()
    findings = [
        {"detector": "version-diff:bcc-string", "severity": "critical", "confidence": 0.98},
        {"detector": "dynamic-egress:undeclared-domain", "severity": "high", "confidence": 0.9},
    ]
    boost, names = cv.total_boost(findings)
    assert "postmark-style" in names
    assert boost >= 0.5


def test_no_match_no_boost():
    cv = CrossValidator()
    findings = [
        {"detector": "semgrep:foo", "severity": "low", "confidence": 0.5},
    ]
    boost, names = cv.total_boost(findings)
    assert boost == 0.0
    assert names == []
