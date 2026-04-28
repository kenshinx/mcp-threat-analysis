# postmark_like — synthetic malicious-MCP fixture

**Not a real package. Do not publish, install, or run.** This is a deliberately
malicious-shaped MCP server used to drive end-to-end smoke tests for the
`static_analysis` / `semantic_analysis` / `risk_scoring` pipeline.

It mirrors the public postmark-mcp v1.0.16 supply-chain incident in shape
(silent BCC exfiltration of every outgoing email) without copying any of that
package's actual code. Every "malicious" element below is synthetic.

## What each file should trip

| File | Detector | Layer |
|---|---|---|
| `package.json` `scripts.postinstall` (`curl … \| sh`) | `manifest:install-hook-network-or-exec` (critical) | static_analysis |
| `src/email_tool.ts` `Bcc: "exfil@attacker.example"` | `mcp-tool-bcc-pattern` (E-SILENT-EXFIL) | static_analysis |
| `src/index.ts` `eval(atob("…"))` | `mcp-obfuscated-base64-exec-js` (E-OBFUSCATION) | static_analysis |
| `src/index.ts` `child_process.execSync("/bin/sh -c " + cmd)` | `mcp-tool-shell-injection-js` (CWE-78) | static_analysis |
| `src/index.ts` description `"Additionally collects …"` | `tool-poisoning-also-does` (Cisco-translated) | static_analysis |
| `src/index.ts` description `"actually secretly uploads"` | `tool-poisoning-secretly` (Cisco-translated) | static_analysis |
| `src/index.ts` description with `​` ZWSP | `char-layer` (when `tools` row is seeded) | semantic_analysis |
| Schema declares `{to,subject,body}` only, code adds `Bcc` | `schema-code-alignment` (when LLM key set) | semantic_analysis |

`risk_scoring` then aggregates these; `manifest:install-hook-network-or-exec`
alone is critical and should land the server in `triage_queue` at P0.

## Running it through the pipeline

```bash
mta-static src/mcp_threat_analysis/tests/fixtures/postmark_like \
    --version 0.0.1-fixture --lang typescript --artifact-type git_repo
# Then (after seeding tools rows):
mta-semantic --server-id <uuid> --version 0.0.1-fixture
mta-risk aggregate <uuid>
```
