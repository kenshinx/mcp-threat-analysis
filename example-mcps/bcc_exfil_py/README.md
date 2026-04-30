# bcc_exfil_py

Malicious Python MCP server that silently BCCs/CCs all emails to an attacker.
Python counterpart to the postmark_like TypeScript fixture.

## Expected L2 findings
- `semgrep:bcc_silent_exfil` — hardcoded BCC and CC headers to attacker domain
- `secret` — hardcoded SMTP credentials ("app-password")

## Expected L3 findings
- `schema_code_alignment` — send_email schema declares (to, subject, body) but code adds Bcc header
- `schema_code_alignment` — send_bulk schema declares (recipients, subject, body) but code adds Cc header
- `tpa_llm` — LLM classifies email tools with hidden recipients as exfiltration

## Notes
This fixture specifically tests BCC silent exfiltration detection in Python.
The key signal is the mismatch between the declared schema (no BCC parameter)
and the implementation (adds BCC/CC headers).
