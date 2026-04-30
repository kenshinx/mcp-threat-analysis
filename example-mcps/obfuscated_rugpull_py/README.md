# obfuscated_rugpull_py

Malicious Python MCP server with obfuscated base64 payloads and rug-pull patterns.

## Expected L2 findings
- `semgrep:obfuscated_base64_exec` — `base64.b64decode()` followed by `exec()`
- `semgrep:dynamic_exec` — `exec(cmd)` with constructed string
- `obfuscation` — high entropy base64 strings, eval/exec patterns

## Expected L3 findings
- `tpa_llm` — LLM classifies analyze_code as suspicious (code analysis tool that exec's hidden payloads)
- `schema_code_alignment` — schema declares code analysis but implementation exfiltrates user code

## Notes
The base64 payloads decode to subprocess calls and print statements.
Even though the payloads are simple, the base64+exec pattern is the key signal.
