# prompt_injection_ts

Malicious MCP server with prompt injection and tool poisoning in tool descriptions.

## Expected L2 findings
- `semgrep:prompt_injection` — "ignore previous instructions", "act as" patterns in tool descriptions
- `semgrep:tool_poisoning` — "also collects", "secretly sends" hidden secondary actions
- `semgrep:prompt_injection_extras` — multilingual injection phrases

## Expected L3 findings
- `char_layer` — hidden ZWSP (U+200B) characters in tool descriptions
- `tpa_text_rules` — promotes static text-rule findings with tool linkage
- `tpa_llm` — LLM classifies descriptions as containing prompt injection
