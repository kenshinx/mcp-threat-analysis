# Unified Response Schema

All semantic_analysis LLM detectors return a JSON object. Common fields shared by every detector:

```json
{
  "verdict": "clean | suspicious | malicious",
  "confidence": 0.0,
  "evidence_quotes": ["..."],
  "explanation": "..."
}
```

Detector-specific extensions:

- TPA detection adds `categories`: array of `instruction_override`, `role_hijack`,
  `data_exfil`, `tool_chain_hijack`, `hidden_format`, `other`.
- Schema-Code Alignment returns `alignment_score` (0–10), `aligned` (boolean),
  `behavioral_diff` (array of `{kind, declared, actual}`), `confidence`,
  `explanation`. `verdict` is omitted.
- Tool capability classification returns `capabilities`: array of strings drawn
  from the supplied vocabulary.

Models MUST output a single JSON object with no surrounding prose. Trailing
commentary will be discarded.
