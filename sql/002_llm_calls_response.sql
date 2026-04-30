-- Add response_json column to llm_calls for DB-backed cache (phase 2)
-- and audit trail of LLM responses.
-- Note: 001_schema.sql has been updated to include this column for fresh
-- installs. This migration exists only for existing deployments.
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS response_json JSONB;
