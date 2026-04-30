"""Centralized settings, loaded once from environment."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    database_url: str
    s3_bucket: str | None
    workdir_root: str

    semgrep_bin: str
    codeql_bin: str
    trufflehog_bin: str
    gitleaks_bin: str
    osv_scanner_bin: str
    pip_audit_bin: str
    npm_bin: str

    semgrep_timeout_s: int
    codeql_timeout_s: int
    artifact_max_bytes: int

    # LLM provider: "anthropic" or "openai_compatible".
    # openai_compatible covers OpenAI itself and any OpenAI-API-compatible
    # endpoint (Volcengine Ark, DeepSeek, Together, vLLM, etc).
    llm_provider: str
    llm_base_url: str | None
    llm_api_key: str | None
    llm_model_batch: str
    llm_model_realtime: str
    # Kept for back-compat; only used when llm_provider == "anthropic" and
    # llm_api_key is unset.
    anthropic_api_key: str | None
    embedding_model: str
    embedding_dim: int

    llm_daily_budget_usd: float
    llm_cache_ttl_days: int

    weights_yaml_path: str | None


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv(
            "MTA_DATABASE_URL",
            "postgresql+asyncpg://mta:mta@localhost:5432/mta",
        ),
        s3_bucket=os.getenv("MTA_S3_BUCKET"),
        workdir_root=os.getenv("MTA_WORKDIR_ROOT", "/tmp/mta-workdir"),
        semgrep_bin=os.getenv("MTA_SEMGREP_BIN", "semgrep"),
        codeql_bin=os.getenv("MTA_CODEQL_BIN", "codeql"),
        trufflehog_bin=os.getenv("MTA_TRUFFLEHOG_BIN", "trufflehog"),
        gitleaks_bin=os.getenv("MTA_GITLEAKS_BIN", "gitleaks"),
        osv_scanner_bin=os.getenv("MTA_OSV_BIN", "osv-scanner"),
        pip_audit_bin=os.getenv("MTA_PIP_AUDIT_BIN", "pip-audit"),
        npm_bin=os.getenv("MTA_NPM_BIN", "npm"),
        semgrep_timeout_s=int(os.getenv("MTA_SEMGREP_TIMEOUT", "300")),
        codeql_timeout_s=int(os.getenv("MTA_CODEQL_TIMEOUT", "600")),
        artifact_max_bytes=int(os.getenv("MTA_ARTIFACT_MAX_BYTES", str(200 * 1024 * 1024))),
        llm_provider=os.getenv("MTA_LLM_PROVIDER", "anthropic").strip().lower(),
        llm_base_url=os.getenv("MTA_LLM_BASE_URL") or None,
        llm_api_key=os.getenv("MTA_LLM_API_KEY") or None,
        llm_model_batch=os.getenv(
            "MTA_LLM_MODEL_BATCH", "claude-haiku-4-5-20251001"
        ),
        llm_model_realtime=os.getenv(
            "MTA_LLM_MODEL_REALTIME", "claude-sonnet-4-6"
        ),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        embedding_model=os.getenv("MTA_EMBEDDING_MODEL", "text-embedding-3-small"),
        embedding_dim=int(os.getenv("MTA_EMBEDDING_DIM", "1536")),
        llm_daily_budget_usd=float(os.getenv("MTA_LLM_DAILY_BUDGET_USD", "200")),
        llm_cache_ttl_days=int(os.getenv("MTA_LLM_CACHE_TTL_DAYS", "30")),
        weights_yaml_path=os.getenv("MTA_L6_WEIGHTS_YAML"),
    )
