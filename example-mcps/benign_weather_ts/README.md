# benign_weather_ts

Benign MCP server for weather information. Should produce minimal/no findings.

## Expected L2 findings
- None (or minimal) — uses fetch only to declared egress domain, no shell exec, no file access, no secrets in code

## Expected L3 findings
- None — clean tool descriptions, no hidden actions, no schema-code mismatch, proper egress declaration

## Notes
This is a negative test case. The server only calls a well-known weather API
with user-provided city names. API key comes from environment variable, not
hardcoded. Egress domain is declared in server.json.
