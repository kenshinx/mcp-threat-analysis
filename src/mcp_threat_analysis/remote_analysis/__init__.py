"""remote_analysis layer (P1).

Probes live MCP servers (streamable-HTTP / SSE / stdio) and reuses the
existing static_summaries → semantic_analysis pipeline by synthesizing a
minimal `static_summaries` row of kind='remote' so rule-based semantic
detectors (`char:hidden-unicode`, `shadow:*`, `tpa-llm`, `untrusted-content`)
run unchanged on remote servers.

P1 scope: streamable-HTTP transport only; one-shot `mta-remote scan`; three
snapshot detectors (TLS expiry, missing auth, protocol-version mismatch).
Drift detection and recurring `watch` daemon are P2.
"""
