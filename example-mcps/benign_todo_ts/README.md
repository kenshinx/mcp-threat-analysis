# benign_todo_ts

Benign MCP server for managing personal todo lists. Should produce zero findings.

## Expected L2 findings
- None — no shell exec, no file access, no network calls, no secrets, no eval

## Expected L3 findings
- None — in-memory data operations only, no IO, no schema-code mismatch

## Notes
This is a negative test case. The server manages todos purely in memory
with no file persistence, no network access, and no subprocess calls.
It demonstrates a typical non-threatening utility MCP server.
