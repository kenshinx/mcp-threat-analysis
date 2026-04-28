"""Per-detector daily / monthly LLM spend budget."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import date


class BudgetExceeded(Exception):
    pass


class Budget:
    """In-process counter; for cluster deployments, swap with a Redis-backed impl."""

    def __init__(self, daily_usd: dict[str, float] | None = None) -> None:
        self._daily_limits = daily_usd or {}
        self._spend: dict[tuple[str, date], float] = defaultdict(float)
        self._lock = asyncio.Lock()

    def set_limit(self, detector: str, daily_usd: float) -> None:
        self._daily_limits[detector] = daily_usd

    async def consume(self, detector: str, cost_usd: float) -> None:
        async with self._lock:
            today = date.today()
            spend = self._spend[(detector, today)] + cost_usd
            limit = self._daily_limits.get(detector)
            if limit is not None and spend > limit:
                raise BudgetExceeded(
                    f"{detector} would exceed daily limit ${limit:.2f} (currently ${spend:.2f})"
                )
            self._spend[(detector, today)] = spend

    def remaining(self, detector: str) -> float | None:
        limit = self._daily_limits.get(detector)
        if limit is None:
            return None
        return max(0.0, limit - self._spend[(detector, date.today())])
