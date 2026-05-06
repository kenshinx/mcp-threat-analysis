# mcp-threat-analysis

Whole-internet detection platform for malicious / vulnerable Model Context
Protocol (MCP) servers. This repository implements the **static analysis**,
**semantic / LLM analysis**, and **risk aggregation / scoring** layers of the
design described in
[`docs/恶意 MCP 检测可执行技术方案.md`](docs/恶意%20MCP%20检测可执行技术方案.md).

Discovery, canonicalization, runtime / temporal analysis, network sandbox, and
disclosure are out of scope for this codebase but their interfaces are defined
where `static_analysis` / `semantic_analysis` / `risk_scoring` produce or
consume their data.

## Repository layout

```
docs/                              # Design docs (master + per-layer sub-system)
sql/                               # Database schema (Postgres + pgvector)
  001_schema.sql                   # Base schema
  002_llm_calls_response.sql       # llm_calls.response_json column
  003_remote_observations.sql      # remote_observations table + extends findings.layer enum
LICENSES/                          # Third-party attribution (Apache-2.0 from Cisco)
example-mcps/                      # 16 example fixtures (8 malicious + 3 benign + ...)
src/mcp_threat_analysis/
  common/                          # Shared models, DB engine, logging, subprocess wrapper
  static_analysis/                 # Static analysis layer
    target_loader.py               # Fetch/extract artifact -> WorkDir
    extractors/                    # Tool-handler locator, AST IO summary, string bag
    analyzers/                     # Semgrep, CodeQL, secret, SCA, manifest, reputation, obfuscation
    rules/semgrep/
      self/                        # Self-authored rules (code/text/manifest)
      translated_from_cisco/       # Translated from cisco-ai-defense/mcp-scanner YARA rules
    orchestrator.py
    persistence.py
    cli.py                         # mta-static
  semantic_analysis/               # Semantic / LLM layer
    detectors/                     # char_layer, tpa_text_rules, tpa_llm, shadowing,
                                   # schema_code_alignment, toxic_flow, untrusted_content
    alignment/                     # AlignmentOrchestrator + cross-file dataflow
    llm/                           # Provider-pluggable LLM client (Anthropic + OpenAI-compatible),
                                   # async semaphore concurrency, budget, in-process cache,
                                   # llm_calls audit-row persistence
    embeddings/                    # encoder + pgvector shadowing index
    prompts/                       # Markdown prompt templates
    orchestrator.py
    cli.py                         # mta-semantic
  risk_scoring/                    # Risk aggregation, scoring, triage routing
    aggregator.py
    cross_validator.py
    triage_router.py
    lifecycle.py
    weights.py
    popularity.py
    ingestor.py                    # Polling watcher of findings.updated_at
    persistence.py                 # Read-side helpers
    api/server.py                  # FastAPI read API + lifecycle POSTs (CORS-enabled)
    cli.py                         # mta-risk
  remote_analysis/                 # Live MCP-server probing layer (P1)
    transport/                     # streamable_http (P1); sse / stdio land in P3
    detectors/                     # tls / auth / protocol — snapshot-only for P1
    orchestrator.py                # probe → detect → persist
    persistence.py                 # remote_observations + synthesize tools/static_summaries
    cli.py                         # mta-remote
  tests/{static_analysis,semantic_analysis,risk_scoring,remote_analysis}/   # Unit tests
```

## Prerequisites

- Python 3.11+
- Postgres 15+ with `vector`, `pgcrypto`, `pg_trgm`, `fuzzystrmatch` extensions
- External binaries on `PATH` (each is optional; the analyzer skips itself if
  the binary is missing):
  `semgrep`, `codeql`, `trufflehog`, `gitleaks`, `osv-scanner`, `pip-audit`,
  `npm`
- An LLM API key for `semantic_analysis` LLM detectors (Anthropic Messages API
  *or* any OpenAI Chat Completions-compatible endpoint — Volcengine Ark, DeepSeek,
  vLLM, Together, etc.). Without a valid key the LLM client raises
  `LLMUnavailable`, the rule-based detectors still run, and the LLM detectors
  short-circuit cleanly.

## Setup

```bash
# 1. Install Python deps
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Configure environment
cp .env.example .env
$EDITOR .env

# 3. Initialize database
createdb mta
psql -d mta -c "CREATE EXTENSION IF NOT EXISTS vector;
                CREATE EXTENSION IF NOT EXISTS pgcrypto;
                CREATE EXTENSION IF NOT EXISTS pg_trgm;
                CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;"
psql -d mta -f sql/001_schema.sql
psql -d mta -f sql/002_llm_calls_response.sql   # adds llm_calls.response_json
psql -d mta -f sql/003_remote_observations.sql  # adds remote_observations + extends findings.layer
```

### LLM provider configuration

The semantic layer's LLM client is provider-pluggable via env vars:

```bash
# Anthropic Messages API (default)
MTA_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Or any OpenAI Chat Completions-compatible endpoint
MTA_LLM_PROVIDER=openai_compatible
MTA_LLM_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
MTA_LLM_API_KEY=...
MTA_LLM_MODEL_PRIMARY=glm-5.1
MTA_LLM_MODEL_FALLBACK=...
```

Concurrency caps default to 3 for Anthropic and 16 for OpenAI-compatible
providers; both can be overridden. Every call (including cache hits and
errors) is persisted to the `llm_calls` audit table and linked back to its
finding via `evidence.llm_call_id`.

## Running

### Run static analysis against a local archive or directory

```bash
mta-static ./path/to/artifact.tgz \
    --version 1.2.3 \
    --lang typescript \
    --artifact-type npm_tarball
```

The CLI prints findings as JSON and (unless `--no-persist`) inserts them into
`findings` and writes a `static_summaries` row consumed by `semantic_analysis`.

### Run semantic analysis against a server already scanned by static_analysis

```bash
mta-semantic --server-id <UUID> --version 1.2.3
```

Without a valid LLM API key, only the rule-based detectors (`char-layer`,
`tpa-text`, `shadowing`, `untrusted-content`) run.

### risk_scoring — aggregate one server, or start the polling ingestor

```bash
# One-shot
mta-risk aggregate <server-uuid>

# Background daemon: poll findings.updated_at every 60s, re-aggregate
# affected servers, push P0/P1 to triage_queue
mta-risk ingest
```

### remote_analysis — probe a live MCP server (P1)

`mta-remote scan` is the entry point for the remote_analysis layer. It probes
a live MCP endpoint over streamable-HTTP (`initialize` → `tools/list` plus
`resources/list` / `prompts/list` when advertised), captures TLS cert details,
runs the P1 snapshot detectors, and writes a `remote_observations` row plus a
synthetic `tools` row per reported tool — so the existing semantic-layer
rule-based detectors (`char:hidden-unicode` / `shadow:*` / `tpa-llm` /
`untrusted-content:unmarked`) run on remote servers unchanged.

```bash
# One-shot probe + persist
mta-remote scan https://mcp.example.com/mcp

# With OAuth bearer
mta-remote scan https://mcp.example.com/mcp --header "Authorization=Bearer $TOKEN"

# Custom server name + tighter timeout
mta-remote scan https://mcp.example.com/mcp --canonical-name acme/email-bot --timeout 8
```

Detectors active in P1: `remote:tls-self-signed` · `remote:tls-near-expiry`
(≤7d → high, ≤30d → medium) · `remote:auth-missing` (non-loopback, non-empty
tools/list, no Authorization / API-key header) · `remote:protocol-version-mismatch`
(reported `protocolVersion` outside the known set).

Drift detectors (tool-added / description-mutated / schema-loosened / etc.)
and the recurring `mta-remote watch` daemon land in P2. SSE and stdio
transports land in P3.

The exit code is `0` on probe success, `2` on transport / handshake failure;
the failure-path observation is still persisted so the failure itself becomes
analyst-visible.

### risk_scoring read API (FastAPI)

```bash
mta-api --port 8080
# GET  /healthz
# GET  /servers                                   # corpus list with risk + active counts
# GET  /servers/{id}/risk                         # server + top findings
# GET  /servers/{id}/risk/history
# GET  /triage?priority=P0&status=pending
# GET  /findings/{id}                             # finding + linked llm_call + related
# GET  /corpus/heatmap                            # detector × server matrix
# POST /findings/{id}/{suppress|confirm|false-positive}
```

CORS is enabled for `http://localhost:7137` and `http://localhost:5173` so
read-only browser clients can consume the API directly.

## Tests

```bash
pytest -q
```

Unit tests in `src/mcp_threat_analysis/tests/` exercise pure-rule detectors,
weight tables, cross-validator, string and tool-handler extractors. DB- and
LLM-touching code paths require the integration environment (Postgres +
Anthropic key) and are skipped automatically when those are absent.

## Pipeline data flow

```
ScanTarget ──► static_analysis Orchestrator ─┬─► findings (layer=static_analysis)
                                             └─► static_summaries
                                                     │
                                                     ▼
              semantic_analysis Orchestrator ──► findings (layer=semantic_analysis)
                                                     │
                                                     ▼
              risk_scoring Ingestor (poll findings.updated_at)
                  │
                  ├─► Aggregator → servers.risk_score / risk_priority
                  │              + server_risk_history
                  └─► TriageRouter → triage_queue (P0/P1)
                                                     │
                                                     ▼
                                           disclosure (out of scope)
```
