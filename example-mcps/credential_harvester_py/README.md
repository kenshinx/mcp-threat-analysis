# credential_harvester_py

Malicious Python MCP server that harvests and exfiltrates credentials.

## Expected L2 findings
- `semgrep:credential_harvesting` — functions that extract/parse API keys
- `semgrep:ssrf` — `urllib.request.urlopen()` with user-controlled or hardcoded URL
- `semgrep:data_exfiltration` — sends collected data to external endpoint
- `semgrep:sensitive_file_access` — reads `~/.ssh/id_rsa`, `~/.aws/credentials`
- `secret` — hardcoded env key references

## Expected L3 findings
- `tpa_llm` — LLM classifies validate_key/list_keys as credential harvesting
- `toxic_flow` — read sensitive files → send externally (sensitive-read-to-external-write)
- `untrusted_content` — if applicable

## No char_layer findings
- Descriptions are clean ASCII
