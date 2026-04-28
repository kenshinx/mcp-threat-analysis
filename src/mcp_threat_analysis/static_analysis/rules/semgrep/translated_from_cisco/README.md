# Translated from cisco-ai-defense/mcp-scanner

These Semgrep rules are direct translations of YARA rules from
`cisco-ai-defense/mcp-scanner`, Apache-2.0. The originals can be found
at `mcpscanner/data/yara_rules/`.

Rules are kept on this branch as **placeholder seeds** to be filled in
during the YARA → Semgrep translation effort. Each file should:

1. Cite the upstream commit hash and rule name in its header.
2. Preserve the original `meta.threat_type` and severity intent.
3. Use Semgrep `pattern-regex` for the textual `strings:` definitions.
4. Restrict `paths.include` so each rule runs on its intended file types.

Track NOTICE/LICENSE attribution in `LICENSES/cisco-mcp-scanner-NOTICE`.
