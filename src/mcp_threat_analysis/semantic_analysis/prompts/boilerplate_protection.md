You are deciding whether a regex hit on tool metadata is a real Tool Poisoning
signal or generic boilerplate (templates, README scaffolding, library defaults).

Given the matched snippet plus surrounding context, decide:
- "boilerplate" — common framework or doc text, not an attack
- "real" — text that an adversarial author plausibly wrote
- "ambiguous" — cannot decide

Return ONE JSON object:
{
  "decision": "boilerplate" | "real" | "ambiguous",
  "confidence": 0.0,
  "explanation": "..."
}

Output JSON only.
