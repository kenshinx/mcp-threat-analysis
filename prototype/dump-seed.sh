#!/usr/bin/env bash
# Dump live PG state into seed.json for the prototype.
# Re-run after detector changes / new fixture runs to refresh the prototype data.
#
# Usage: prototype/dump-seed.sh > prototype/seed.json
set -euo pipefail

PG="${PG:-PGPASSWORD=mta psql -h 127.0.0.1 -p 5432 -U mta -d mta -tAc}"

q() { eval "$PG \"\$1\""; }

cat <<JSON
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "servers":          $(q "SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.risk_score DESC NULLS LAST), '[]'::jsonb) FROM (
                            SELECT id, canonical_name, risk_score, risk_priority, risk_updated_at,
                                   weights_version, status,
                                   (SELECT count(*) FROM findings f WHERE f.server_id=s.id AND f.status='active') AS active_finding_count,
                                   (SELECT count(*) FROM findings f WHERE f.server_id=s.id) AS total_finding_count
                              FROM servers s
                          ) s"),
  "triage":           $(q "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.priority, t.enqueued_at ASC), '[]'::jsonb) FROM (
                            SELECT t.id, t.server_id, s.canonical_name, t.priority, t.status,
                                   t.enqueued_at, s.risk_score, t.assignee
                              FROM triage_queue t JOIN servers s ON s.id=t.server_id
                          ) t"),
  "findings":         $(q "SELECT COALESCE(jsonb_agg(to_jsonb(f)), '[]'::jsonb) FROM (
                            SELECT id, server_id, detector, layer, severity, confidence, evidence,
                                   issue_code, status, created_at, artifact_ref
                              FROM findings
                          ) f"),
  "tools":            $(q "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (
                            SELECT id, server_id, name, description, input_schema, annotations
                              FROM tools
                          ) t"),
  "tool_capabilities": $(q "SELECT COALESCE(jsonb_agg(to_jsonb(tc)), '[]'::jsonb) FROM (
                            SELECT tool_id, capabilities, classifier, content_hash, classified_at
                              FROM tool_capabilities
                          ) tc"),
  "static_summaries": $(q "SELECT COALESCE(jsonb_agg(to_jsonb(s)), '[]'::jsonb) FROM (
                            SELECT server_id, version, summary, written_at
                              FROM static_summaries
                          ) s"),
  "risk_history":     $(q "SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY h.scored_at DESC), '[]'::jsonb) FROM (
                            SELECT server_id, scored_at, score, priority, finding_count, weights_version
                              FROM server_risk_history
                          ) h"),
  "llm_calls":        $(q "SELECT COALESCE(jsonb_agg(to_jsonb(l)), '[]'::jsonb) FROM (
                            SELECT id, detector, model, prompt_sha, input_sha, tokens_in, tokens_out,
                                   cost_usd, status, finding_id, response_json, created_at
                              FROM llm_calls
                          ) l"),
  "remote_observations": $(q "SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.probed_at DESC), '[]'::jsonb) FROM (
                            SELECT id, server_id, probed_at, transport, endpoint, ok, protocol_ver,
                                   server_info, capabilities, tools, resources, prompts, tls,
                                   auth_kind, latency_ms, error
                              FROM remote_observations
                          ) o" 2>/dev/null || echo '[]')
}
JSON
