"""LLM client used by all semantic_analysis detectors.

Supports two providers, selected via `MTA_LLM_PROVIDER`:
- "anthropic"          → Anthropic Messages API with ephemeral prompt cache
- "openai_compatible"  → any endpoint speaking the OpenAI Chat Completions
                         API (OpenAI itself, Volcengine Ark, DeepSeek, vLLM,
                         Together, …). Configure via MTA_LLM_BASE_URL +
                         MTA_LLM_API_KEY + MTA_LLM_MODEL_*.

Output is forced to JSON; the response is parsed and returned as a dict.
Cost is tracked when the model id is known to `_PRICES`; otherwise reported
as 0.0 (caller's budget still applies, just not metered).

Concurrency is bounded by an internal `asyncio.Semaphore` so that parallel
detectors / tool fan-outs don't exceed provider rate limits.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Literal

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ...common.config import get_settings
from ...common.logging import get_logger
from .budget import Budget
from .cache import LLMCache, sha

log = get_logger(__name__)


class LLMUnavailable(Exception):
    pass


@dataclass(slots=True)
class LLMResponse:
    parsed: dict[str, Any]
    raw_text: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    cache_hit: bool


# USD per 1M tokens (input, output). Unknown models report 0.0 cost.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-7": (15.0, 75.0),
}


def _default_concurrency(provider: str) -> int:
    if provider == "anthropic":
        return 3
    return 16


class LLMClient:
    def __init__(
        self,
        cache: LLMCache | None = None,
        budget: Budget | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        self.cache = cache or LLMCache()
        self.budget = budget or Budget()
        self._client: Any = None
        self._provider: str | None = None
        if max_concurrency is not None and max_concurrency > 0:
            self._sem = asyncio.Semaphore(max_concurrency)
        else:
            s = get_settings()
            self._sem = asyncio.Semaphore(
                _default_concurrency(s.llm_provider)
            )

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        s = get_settings()
        provider = s.llm_provider
        if provider == "anthropic":
            api_key = s.llm_api_key or s.anthropic_api_key
            if not api_key:
                raise LLMUnavailable(
                    "no API key set (MTA_LLM_API_KEY or ANTHROPIC_API_KEY)"
                )
            try:
                from anthropic import AsyncAnthropic
            except ImportError as e:
                raise LLMUnavailable("anthropic SDK not installed") from e
            self._client = AsyncAnthropic(api_key=api_key)
        elif provider == "openai_compatible":
            if not s.llm_api_key:
                raise LLMUnavailable("MTA_LLM_API_KEY not set")
            if not s.llm_base_url:
                raise LLMUnavailable("MTA_LLM_BASE_URL not set")
            try:
                from openai import AsyncOpenAI
            except ImportError as e:
                raise LLMUnavailable(
                    "openai SDK not installed (pip install openai)"
                ) from e
            self._client = AsyncOpenAI(
                api_key=s.llm_api_key,
                base_url=s.llm_base_url,
            )
        else:
            raise LLMUnavailable(
                f"unknown MTA_LLM_PROVIDER={provider!r}; "
                "expected 'anthropic' or 'openai_compatible'"
            )
        self._provider = provider
        return self._client

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=15),
        reraise=True,
    )
    async def call(
        self,
        *,
        detector: str,
        prompt: str,
        payload: str,
        mode: Literal["realtime", "batch"] = "batch",
        max_tokens: int = 1024,
    ) -> LLMResponse:
        s = get_settings()
        model = s.llm_model_realtime if mode == "realtime" else s.llm_model_batch
        cached = self.cache.get(detector, model, prompt, payload)
        if cached is not None:
            return LLMResponse(
                parsed=cached,
                raw_text=json.dumps(cached),
                model=model,
                tokens_in=0,
                tokens_out=0,
                cost_usd=0.0,
                cache_hit=True,
            )
        async with self._sem:
            client = self._ensure_client()
            if self._provider == "anthropic":
                raw, in_tokens, out_tokens = await self._call_anthropic(
                    client, model, prompt, payload, max_tokens
                )
            else:
                raw, in_tokens, out_tokens = await self._call_openai_compatible(
                    client, model, prompt, payload, max_tokens
                )
        parsed = _parse_json(raw)
        cost = _cost(model, in_tokens, out_tokens)
        await self.budget.consume(detector, cost)
        self.cache.put(detector, model, prompt, payload, parsed)
        log.info(
            "llm.call",
            detector=detector,
            provider=self._provider,
            model=model,
            tokens_in=in_tokens,
            tokens_out=out_tokens,
            cost_usd=cost,
        )
        return LLMResponse(
            parsed=parsed,
            raw_text=raw,
            model=model,
            tokens_in=in_tokens,
            tokens_out=out_tokens,
            cost_usd=cost,
            cache_hit=False,
        )

    async def _call_anthropic(
        self, client, model: str, prompt: str, payload: str, max_tokens: int
    ) -> tuple[str, int, int]:
        resp = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=[
                {
                    "type": "text",
                    "text": prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": payload}],
        )
        text_blocks = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
        raw = "".join(text_blocks).strip()
        return raw, resp.usage.input_tokens, resp.usage.output_tokens

    async def _call_openai_compatible(
        self, client, model: str, prompt: str, payload: str, max_tokens: int
    ) -> tuple[str, int, int]:
        # Many OpenAI-compatible endpoints (Ark, DeepSeek, vLLM) don't accept
        # response_format=json_object — rely on prompt + balanced-brace salvage.
        resp = await client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=0,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": payload},
            ],
        )
        choice = resp.choices[0]
        raw = (choice.message.content or "").strip()
        usage = getattr(resp, "usage", None)
        in_tokens = getattr(usage, "prompt_tokens", 0) or 0
        out_tokens = getattr(usage, "completion_tokens", 0) or 0
        return raw, in_tokens, out_tokens


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip("` \n")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Salvage: take the largest balanced {...} block.
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _cost(model: str, tokens_in: int, tokens_out: int) -> float:
    price = _PRICES.get(model)
    if price is None:
        return 0.0
    in_price, out_price = price
    return (tokens_in * in_price + tokens_out * out_price) / 1_000_000
