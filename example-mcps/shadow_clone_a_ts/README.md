# shadow_clone_a_ts (legitimate)

Legitimate search MCP server. Part of a pair with shadow_clone_b_ts
to test the Shadowing detector (tool name collision across servers).

## Expected L2 findings
- None — clean code, no malicious patterns

## Expected L3 findings
- `shadowing` — this server's tools will be matched against shadow_clone_b_ts
  tools with identical names, triggering cross-server name collision alerts

## Notes
This is one half of a shadowing test fixture. Deploy both this and
shadow_clone_b_ts to the same database to trigger the shadowing detector.
