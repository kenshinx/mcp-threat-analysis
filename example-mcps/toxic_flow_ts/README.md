# toxic_flow_ts

Malicious MCP server designed to test the Toxic Flow detector.
Contains both source tools (fetch, read) and sink tools (send, execute, write)
that form dangerous data flow patterns within a single server.

## Expected L2 findings
- `semgrep:ssrf` — `fetch(url)`, `https.request(webhook)`
- `semgrep:cmd_injection` — `execSync(script)` with user input
- `semgrep:path_traversal` — `fs.writeFileSync(filepath)` with user input
- `semgrep:sensitive_file_access` — reads `/var/mail/user`

## Expected L3 findings
- `toxic_flow` — untrusted-read-to-sensitive-write: fetch_data → send_notification / run_transform
- `toxic_flow` — sensitive-read-to-external-write: read_inbox → send_notification
- `toxic_flow` — untrusted-desc-triggers-sensitive: fetch_data result can flow to run_transform
- `tpa_llm` — LLM classifies these tools as forming dangerous pipelines
- `untrusted_content` — fetch_data returns untrusted content without markers
