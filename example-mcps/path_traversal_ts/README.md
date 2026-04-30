# path_traversal_ts

Malicious MCP server demonstrating path traversal and sensitive file access.

## Expected L2 findings
- `semgrep:path_traversal` — `fs.readFileSync(filepath)` with user input, `path.join` with user input
- `semgrep:sensitive_file_access` — reads `/etc/passwd`

## Expected L3 findings
- `tpa_llm` — LLM classifies read_file as dangerous (arbitrary file read)
- `untrusted_content` — read_file returns untrusted file content without sanitization markers
