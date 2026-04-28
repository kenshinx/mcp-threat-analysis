from mcp_threat_analysis.risk_scoring.weights import detector_to_class, load_weights


def test_detector_to_class_known():
    assert detector_to_class("semgrep:foo") == "static:semgrep"
    assert detector_to_class("char:hidden-unicode") == "semantic:char"
    assert detector_to_class("tpa-llm") == "semantic:tpa-llm"
    assert detector_to_class("llm:schema-code-inconsistency") == "semantic:schema-code"
    assert detector_to_class("toxic-flow:foo") == "semantic:toxic-flow"
    assert detector_to_class("dynamic-egress:undeclared-domain") == "network:dynamic-egress"


def test_detector_to_class_unknown():
    assert detector_to_class("totally-made-up:xyz") == "unknown"


def test_default_weights_loaded():
    w = load_weights()
    assert w.severity["critical"] > w.severity["info"]
    assert w.class_weight("semgrep:foo") == 1.0
    assert w.class_weight("llm:schema-code-inconsistency") == 2.0
