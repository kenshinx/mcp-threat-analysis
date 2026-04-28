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
LICENSES/                          # Third-party attribution (Apache-2.0 from Cisco)
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
    llm/                           # Anthropic client, batch runner, budget, cache
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
    api/server.py                  # FastAPI: /servers/{id}/risk, /triage, lifecycle
    cli.py                         # mta-risk
  tests/{static_analysis,semantic_analysis,risk_scoring}/   # Unit tests
```

## Prerequisites

- Python 3.11+
- Postgres 15+ with `vector`, `pgcrypto`, `pg_trgm`, `fuzzystrmatch` extensions
- External binaries on `PATH` (each is optional; the analyzer skips itself if
  the binary is missing):
  `semgrep`, `codeql`, `trufflehog`, `gitleaks`, `osv-scanner`, `pip-audit`,
  `npm`
- An Anthropic API key for `semantic_analysis` LLM detectors (without it, the
  LLM detectors log a skip and the rules-only detectors still run)

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
```

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

If `ANTHROPIC_API_KEY` is unset, only the rule-based detectors
(`char-layer`, `tpa-text`, `shadowing`, `untrusted-content`) run.

### risk_scoring — aggregate one server, or start the polling ingestor

```bash
# One-shot
mta-risk aggregate <server-uuid>

# Background daemon: poll findings.updated_at every 60s, re-aggregate
# affected servers, push P0/P1 to triage_queue
mta-risk ingest
```

### risk_scoring read API (FastAPI)

```bash
mta-api --port 8080
# GET  /servers/{id}/risk
# GET  /servers/{id}/risk/history
# GET  /triage?priority=P0
# POST /findings/{id}/{suppress|confirm|false-positive}
```

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

## Attribution

The Semgrep rules under
`src/mcp_threat_analysis/static_analysis/rules/semgrep/translated_from_cisco/`
are direct translations of YARA rules from
[`cisco-ai-defense/mcp-scanner`](https://github.com/cisco-ai-defense/mcp-scanner)
(Apache-2.0). See `LICENSES/cisco-mcp-scanner-NOTICE`.

## Documentation

- Master design: [`docs/恶意 MCP 检测可执行技术方案.md`](docs/恶意%20MCP%20检测可执行技术方案.md)
- Static analysis design: [`docs/静态分析层-系统设计.md`](docs/静态分析层-系统设计.md)
- Semantic / LLM analysis design: [`docs/语义LLM分析层-系统设计.md`](docs/语义LLM分析层-系统设计.md)
- Risk scoring design: [`docs/风险聚合评分层-系统设计.md`](docs/风险聚合评分层-系统设计.md)
