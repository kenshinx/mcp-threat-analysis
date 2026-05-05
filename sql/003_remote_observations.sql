-- remote_analysis (P1): probe-time observations of live MCP servers.
-- Each row captures one initialize + tools/list (+resources/list, +prompts/list)
-- round-trip against a streamable-HTTP / SSE / stdio MCP endpoint.

CREATE TABLE IF NOT EXISTS remote_observations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id      UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    probed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    probe_version  TEXT NOT NULL,
    transport      TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    ok             BOOL NOT NULL,
    protocol_ver   TEXT,
    server_info    JSONB,
    capabilities   JSONB,
    tools          JSONB,
    resources      JSONB,
    prompts        JSONB,
    tls            JSONB,
    auth_kind      TEXT,
    latency_ms     INT,
    error          JSONB
);
CREATE INDEX IF NOT EXISTS remote_obs_server_idx
  ON remote_observations(server_id, probed_at DESC);

-- Extend findings.layer CHECK to include the remote_analysis layer value.
-- Drop-then-add because Postgres has no IF EXISTS for CHECK constraints by name
-- portably across versions older than 16; the constraint name is stable.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_layer_check;
ALTER TABLE findings ADD CONSTRAINT findings_layer_check
  CHECK (layer IN ('static_analysis','semantic_analysis','runtime_analysis','network_analysis','remote_analysis'));
