# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project at a glance

Whole-internet detection platform for malicious / vulnerable MCP servers. Implements three layers from the master design (`docs/恶意 MCP 检测可执行技术方案.md`):

- **`static_analysis/`** — static analysis (`src/mcp_threat_analysis/static_analysis/`)
- **`semantic_analysis/`** — semantic / LLM analysis (`src/mcp_threat_analysis/semantic_analysis/`)
- **`risk_scoring/`** — risk aggregation, scoring, triage (`src/mcp_threat_analysis/risk_scoring/`)

Discovery, canonicalization, runtime / temporal analysis, network sandbox, and disclosure are intentionally out of scope here; their interfaces are stubbed where `static_analysis` / `semantic_analysis` / `risk_scoring` produce or consume their data.

## Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# DB init (Postgres 15+ with vector / pgcrypto / pg_trgm / fuzzystrmatch)
psql -d mta -f sql/001_schema.sql
psql -d mta -f sql/002_llm_calls_response.sql   # llm_calls.response_json column

# Run a single layer
mta-static <artifact-path-or-url> --version <ver> --lang <python|typescript|...>
mta-semantic --server-id <uuid> --version <ver>
mta-risk aggregate <server-uuid>     # one-shot
mta-risk ingest                       # polling daemon
mta-api --port 8080                   # risk_scoring read API (FastAPI, CORS enabled)

# Tests
pytest -q
pytest src/mcp_threat_analysis/tests/semantic_analysis/test_char_layer.py -q   # single test
```

External binaries that analyzers shell out to (each is optional — analyzer skips itself when missing):
`semgrep`, `codeql`, `trufflehog`, `gitleaks`, `osv-scanner`, `pip-audit`, `npm`.

## High-level architecture

### Layer boundaries (read this first when modifying detectors)

- **`static_analysis` produces** `findings(layer='static_analysis')` plus `static_summaries.summary` (cached AST/IO summary).
- **`semantic_analysis` consumes** `static_analysis`'s `static_summaries` + the `tools` rows (from discovery/canonicalization) and produces `findings(layer='semantic_analysis')`. It does not re-scan source code; it reads what `static_analysis` wrote.
- **`risk_scoring` consumes** all `findings` (any layer) and produces `servers.risk_score`, `server_risk_history`, `triage_queue`. It has no detectors.

Cross-layer interface lives in two places only: the `findings` table and the `static_summaries` table. Adding a new detector means adding rows to `findings`; adding a new score input means changing the aggregator.

### `static_analysis` internal flow

`TargetLoader` → `extractors` (locator + AST + strings) → `analyzers` (`Semgrep`, `CodeQL`, `Secret`, `SCA`, `Manifest`, `Reputation`, `Obfuscation`) → `persistence.save_static_findings()` writes both `findings` and one `static_summaries` row.

Two extractor outputs (`tool_handlers`, `string_bag`) are passed through every analyzer in `StaticAnalysisContext`. Analyzers must never mutate `tool_handlers`; they may append into `manifest_facts` / `declared_egress_domains` / `sca_deps` / `obfuscation_score`.

Semgrep rules are split into:

- `rules/semgrep/self/{code,text,manifest}/` — self-authored
- `rules/semgrep/translated_from_cisco/` — translated from `cisco-ai-defense/mcp-scanner` YARA rules (Apache-2.0). Each translated file's header cites the upstream rule + commit. License attribution lives in `LICENSES/cisco-mcp-scanner-NOTICE`.

### `semantic_analysis` internal flow

`SemanticAnalysisOrchestrator` loads `static_summaries` + `tools` into a `SemanticAnalysisContext`, links each tool to its `ToolHandler` by name, then runs detectors:

Rule-based (no LLM): `CharLayerDetector`, `TPATextRulesDetector` (re-promotes `static_analysis` text-rule findings as `semantic_analysis` findings with tool linkage), `ShadowingDetector`, `UntrustedContentDetector`.

LLM-based: `TPALLMDetector`, `SchemaCodeAlignmentDetector`, `ToxicFlowDetector`. All LLM access goes through `semantic_analysis.llm.LLMClient`, which supports two providers via `MTA_LLM_PROVIDER`: `"anthropic"` (Anthropic Messages API with ephemeral prompt caching) or `"openai_compatible"` (any OpenAI Chat Completions-compatible endpoint — Volcengine Ark, DeepSeek, vLLM, Together, etc; configure via `MTA_LLM_BASE_URL` + `MTA_LLM_API_KEY` + `MTA_LLM_MODEL_*`). Tenacity retries, in-process result cache, per-detector budget. Concurrency is bounded by an internal `asyncio.Semaphore` with provider-specific defaults (anthropic=3, openai_compatible=16). Without a valid API key, the LLM client raises `LLMUnavailable` and detectors short-circuit cleanly.

Every LLM call (live, cache hit, or error) is persisted as an `llm_calls` audit row with `model`, `prompt_sha`, `input_sha`, token counts, `cost_usd`, `status`, and the full `response_json`. Detectors that emit a finding linked to a call set `evidence['llm_call_id']` so the prototype's Finding-detail "LLM call" tab and `GET /findings/{id}` can join the two.

Schema-Code alignment is the most architecturally important detector — it is split into the Cisco-style component pipeline:

```
CrossFileDataflowAnalyzer → AlignmentPromptBuilder → LLMClient → AlignmentResponseValidator
```

This composition is preserved on purpose: the static `IOSummary` is what gets sent to the LLM, not the source code. When extending alignment, add fields to `EnrichedHandler` and the prompt schema together.

### `risk_scoring` internal flow

`Ingestor` (polling, 60s default) discovers servers with new finding activity → `Aggregator` recomputes `risk_score = base * (1 + cross_validation_boost) * (1 + popularity)` → `TriageRouter` enqueues P0/P1 servers (with 24h debounce) → downstream disclosure reads `triage_queue`.

Weights are split across two tables in `weights.py`: `severity` and `detector_class`. Mapping from a raw `detector` string to a class key is centralized in `detector_to_class()` — when you add a new detector class, update that function so its findings are scored.

`Lifecycle` is the only place that mutates `findings.status`. Treat it as the single owner of finding state transitions.

## Conventions

- Async throughout — SQLAlchemy 2.x async + asyncpg. Synchronous code only in CLI entrypoints.
- Single shared persistence helper `common.persistence.upsert_findings()` enforces the dedupe key `(server_id, detector, artifact_ref, evidence_key)` and supersedes prior active rows on rewrite. New detectors must populate `evidence['evidence_key']` (or rely on the default `file:line:tool_name`).
- LLM responses are JSON-only; all prompts live in `semantic_analysis/prompts/*.md` and are loaded via `load_prompt()`. Prompts are content-addressable in the cache, so changing the file invalidates the cache automatically.
- Embedding encoder defaults to a deterministic hash so the rest of the pipeline can run offline. Set `MTA_EMBEDDING_PROVIDER=openai` to use real embeddings.
- Logging is `structlog` JSON to stderr; do not add `print()` calls in library code.
- New external-tool integrations should go through `common.subprocess_runner.run()` so timeouts and process lifecycle are handled uniformly.

## What lives where

- DB schema source of truth: `sql/001_schema.sql` + numbered migrations (`sql/002_*.sql`, ...). Changes here must be reflected in the SQLAlchemy text() queries; there is no ORM model layer. The `findings.layer` column uses string values `'static_analysis'` / `'semantic_analysis'` / `'runtime_analysis'` / `'network_analysis'` (the latter two reserved for out-of-scope layers).
- Settings (env vars): `common/config.py`. All env reads go through `get_settings()` — do not call `os.getenv` from analyzer code.
- Design docs: `docs/`. The master doc plus three sub-system docs are the canonical reference for module boundaries; the design doc and code agree by intent, so update both when you change behavior.
- `risk_scoring/api/server.py` exposes the read API + lifecycle POSTs. Read endpoints: `/healthz`, `/servers`, `/servers/{id}/risk[/history]`, `/triage`, `/findings/{id}` (joins `llm_calls` and same-tool related findings), `/corpus/heatmap`. CORS allows `http://localhost:7137` and `http://localhost:5173` so browser clients can consume the API directly.
