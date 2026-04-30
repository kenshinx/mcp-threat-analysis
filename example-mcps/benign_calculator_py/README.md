# benign_calculator_py

Benign Python MCP server for pure math calculations. Should produce zero findings.

## Expected L2 findings
- None — no shell exec, no file access, no network calls, no secrets

## Expected L3 findings
- None — no IO operations, no schema-code mismatch, no hidden actions

## Notes
This is a negative test case. The server performs only pure computation
with no IO, network access, file reads, or subprocess calls.
It is the ideal "clean" baseline for testing that detectors have low
false-positive rates.
