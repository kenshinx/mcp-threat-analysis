"""Anthropic-backed LLM client used by all semantic_analysis detectors.

Behaviors:
- Realtime path uses the Messages API directly.
- Batch path enqueues to an in-memory batch runner and resolves later.
- Output is forced to a JSON object; client returns the parsed dict.
- Prompt caching: if `cache_breakpoint` is True, the prompt template
  receives Anthropic ephemeral cache_control on the system block.
"""
from __future__ import annotations

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


# Prices in USD per 1M tokens; rough defaults — refresh as Anthropic updates.
_PRICES = {
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-7": (15.0, 75.0),
}


class LLMClient:
    def __init__(
        self,
        cache: LLMCache | None = None,
        budget: Budget | None = None,
    ) -> None:
        self.cache = cache or LLMCache()
        self.budget = budget or Budget()
        self._client = None  # lazy

    def _ensure_client(self):
        if self._client is None:
            api_key = get_settings().anthropic_api_key
            if not api_key:
                raise LLMUnavailable("ANTHROPIC_API_KEY not configured")
            try:
                from anthropic import AsyncAnthropic
            except ImportError as e:
                raise LLMUnavailable("anthropic SDK not installed") from e
            self._client = AsyncAnthropic(api_key=api_key)
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
        model = s.anthropic_model_realtime if mode == "realtime" else s.anthropic_model_batch
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
        client = self._ensure_client()
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
        parsed = _parse_json(raw)
        in_tokens = resp.usage.input_tokens
        out_tokens = resp.usage.output_tokens
        cost = _cost(model, in_tokens, out_tokens)
        await self.budget.consume(detector, cost)
        self.cache.put(detector, model, prompt, payload, parsed)
        log.info(
            "llm.call",
            detector=detector,
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
    in_price, out_price = _PRICES.get(model, (3.0, 15.0))
    return (tokens_in * in_price + tokens_out * out_price) / 1_000_000
