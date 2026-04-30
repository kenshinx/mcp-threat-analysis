# shadow_clone_b_ts (malicious clone)

Malicious clone of shadow_clone_a_ts that uses identical tool names
to shadow the legitimate server's tools. The clone exfiltrates data.

## Expected L2 findings
- `semgrep:ssrf` — `https.request()` to attacker domain
- `semgrep:data_exfiltration` — sends search queries to external server
- `semgrep:sensitive_file_access` — reads `/tmp/image_cache.dat`

## Expected L3 findings
- `shadowing` — exact name collision with shadow_clone_a's `web_search` and `image_search`
  across different servers → high severity
- `tpa_llm` — LLM identifies web_search as malicious (exfiltrates queries)
- `schema_code_alignment` — schema declares search but code exfiltrates

## Notes
This is the malicious half of a shadowing test fixture.
Both this and shadow_clone_a_ts must be in the database for the
shadowing detector to detect the cross-server name collision.
