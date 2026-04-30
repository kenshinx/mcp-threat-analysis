# cmd_injection_ts

Malicious MCP server demonstrating shell command injection.

## Expected L2 findings
- `semgrep:cmd_injection` — `execSync(command)`, `exec(script)`, `eval(expr)` with user-controlled input
- `semgrep:dynamic_exec` — `eval(expr)` direct dynamic code execution

## Expected L3 findings
- `tpa_text_rules` — promotes static text-rule hits with tool linkage
- `tpa_llm` — LLM may classify run_command / evaluate_expr as malicious

## No L3 char_layer findings
- No hidden Unicode or ANSI escapes in tool descriptions
