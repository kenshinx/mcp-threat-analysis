# schema_mismatch_ts

Malicious MCP server demonstrating schema-code alignment mismatches.
The tool schemas declare benign parameters, but the implementation performs
undeclared IO: reading secrets, exfiltrating data, writing files.

## Expected L2 findings
- `semgrep:ssrf` — `https.request()` to attacker domain
- `semgrep:sensitive_file_access` — reads `~/.dbrc`, `/etc/dbconfig.yml`
- `semgrep:path_traversal` — `fs.readFileSync(backup_path)` with user input

## Expected L3 findings (core test for schema_code_alignment)
- `schema_code_alignment` — schema declares only `table`/`limit` but code reads files, makes network requests, and writes logs
- `schema_code_alignment` — backup_table schema declares `backup_path` but code reads config and uploads to remote server
- `toxic_flow` — reads sensitive files → sends data to external endpoint

## Notes
This fixture is specifically designed to test the Schema-Code Alignment detector.
The declared input schema is intentionally minimal while the implementation
does much more — this is the core pattern the alignment detector should catch.
