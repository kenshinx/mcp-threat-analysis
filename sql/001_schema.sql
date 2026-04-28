-- Initial schema for static_analysis / semantic_analysis / risk_scoring.
-- Aligned with master design doc §3.1 plus risk_scoring lifecycle additions.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name  TEXT UNIQUE NOT NULL,
    kind            TEXT CHECK (kind IN ('package','remote','hybrid')),
    transports      TEXT[],
    primary_lang    TEXT,
    first_seen      TIMESTAMPTZ DEFAULT now(),
    last_updated    TIMESTAMPTZ DEFAULT now(),
    risk_score      REAL,
    risk_priority   TEXT,
    risk_updated_at TIMESTAMPTZ,
    weights_version TEXT,
    status          TEXT CHECK (status IN ('active','removed','quarantined')) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS package_versions (
    server_id       UUID REFERENCES servers(id) ON DELETE CASCADE,
    registry        TEXT,
    version         TEXT,
    published_at    TIMESTAMPTZ,
    artifact_sha256 TEXT,
    artifact_url    TEXT,
    publisher       TEXT,
    deps            JSONB,
    PRIMARY KEY (server_id, registry, version)
);

CREATE TABLE IF NOT EXISTS tools (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID REFERENCES servers(id) ON DELETE CASCADE,
    snapshot_ref    TEXT,
    name            TEXT,
    description     TEXT,
    input_schema    JSONB,
    annotations     JSONB,
    description_emb VECTOR(1536)
);
CREATE INDEX IF NOT EXISTS tools_server_idx ON tools(server_id);
CREATE INDEX IF NOT EXISTS tools_name_idx ON tools(name);

CREATE TABLE IF NOT EXISTS findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id         UUID REFERENCES servers(id) ON DELETE CASCADE,
    detector          TEXT NOT NULL,
    layer             TEXT NOT NULL CHECK (layer IN ('static_analysis','semantic_analysis','runtime_analysis','network_analysis')),
    issue_code        TEXT,
    severity          TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence        REAL NOT NULL,
    evidence          JSONB,
    artifact_ref      TEXT,
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','suppressed','superseded','confirmed','false_positive')),
    status_changed_at TIMESTAMPTZ DEFAULT now(),
    superseded_by     UUID REFERENCES findings(id),
    suppressed_reason TEXT,
    created_at        TIMESTAMPTZ DEFAULT now(),
    updated_at        TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_server_idx ON findings(server_id);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status);
CREATE INDEX IF NOT EXISTS findings_layer_idx ON findings(layer);
CREATE UNIQUE INDEX IF NOT EXISTS findings_dedupe_idx
  ON findings(server_id, detector, artifact_ref, (evidence->>'evidence_key'))
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS static_summaries (
    server_id   UUID REFERENCES servers(id) ON DELETE CASCADE,
    version     TEXT,
    summary     JSONB NOT NULL,
    written_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (server_id, version)
);

CREATE TABLE IF NOT EXISTS tool_capabilities (
    tool_id        UUID PRIMARY KEY REFERENCES tools(id) ON DELETE CASCADE,
    classified_at  TIMESTAMPTZ DEFAULT now(),
    capabilities   TEXT[],
    classifier     TEXT,
    content_hash   TEXT
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detector    TEXT,
    model       TEXT,
    prompt_sha  TEXT,
    input_sha   TEXT,
    tokens_in   INT,
    tokens_out  INT,
    cost_usd    NUMERIC(10,4),
    status      TEXT,
    finding_id  UUID REFERENCES findings(id),
    created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS llm_calls_cache_idx
  ON llm_calls(detector, model, prompt_sha, input_sha);

CREATE TABLE IF NOT EXISTS server_risk_history (
    server_id       UUID REFERENCES servers(id) ON DELETE CASCADE,
    scored_at       TIMESTAMPTZ DEFAULT now(),
    score           REAL NOT NULL,
    priority        TEXT,
    finding_count   INT,
    findings_digest JSONB,
    weights_version TEXT,
    PRIMARY KEY (server_id, scored_at)
);

CREATE TABLE IF NOT EXISTS triage_queue (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID REFERENCES servers(id) ON DELETE CASCADE,
    priority    TEXT NOT NULL,
    enqueued_at TIMESTAMPTZ DEFAULT now(),
    assignee    TEXT,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','in_review','resolved')),
    resolution  TEXT CHECK (resolution IN
                ('confirmed_malicious','confirmed_vuln','fp','duplicate')),
    resolved_at TIMESTAMPTZ,
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS triage_status_priority_idx
  ON triage_queue(status, priority, enqueued_at);

CREATE TABLE IF NOT EXISTS server_popularity (
    server_id    UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    pop          REAL,
    computed_at  TIMESTAMPTZ DEFAULT now(),
    raw          JSONB
);

CREATE OR REPLACE FUNCTION findings_set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS findings_updated_at ON findings;
CREATE TRIGGER findings_updated_at BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION findings_set_updated_at();
