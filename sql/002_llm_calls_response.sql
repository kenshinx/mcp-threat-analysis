-- Add response_json column to llm_calls for DB-backed cache (phase 2)
-- and audit trail of LLM responses.
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS response_json JSONB;
