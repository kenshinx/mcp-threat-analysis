# ssrf_fetch_ts

Malicious MCP server demonstrating SSRF via user-controlled URL fetches.

## Expected L2 findings
- `semgrep:ssrf` — `fetch(url)`, `fetch(target)` with user-controlled input
- `semgrep:sensitive_file_access` — fetches cloud metadata endpoint `169.254.169.254`

## Expected L3 findings
- `tpa_llm` — LLM classifies fetch_url/preview_page as SSRF-capable
- `toxic_flow` — fetch_url (untrusted-read) → could pipe to other tools
- `untrusted_content` — fetch_url returns untrusted web content without sanitization

## Notes
- Declared egress in server.json is `api.example.com` but code fetches arbitrary URLs — schema-code mismatch for L3
