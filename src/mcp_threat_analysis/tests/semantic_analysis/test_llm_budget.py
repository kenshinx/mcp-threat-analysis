"""Tests for semantic_analysis.llm.budget — Budget consume/remaining/set_limit."""
from __future__ import annotations

import asyncio

import pytest

from mcp_threat_analysis.semantic_analysis.llm.budget import Budget, BudgetExceeded


@pytest.fixture
def budget():
    return Budget(daily_usd={"tpa-llm": 1.0, "alignment": 0.5})


def test_remaining_no_spend(budget):
    assert budget.remaining("tpa-llm") == 1.0


def test_remaining_unknown_detector(budget):
    assert budget.remaining("unknown") is None


@pytest.mark.asyncio
async def test_consume_within_limit(budget):
    await budget.consume("tpa-llm", 0.3)
    assert budget.remaining("tpa-llm") == pytest.approx(0.7)


@pytest.mark.asyncio
async def test_consume_exact_limit(budget):
    await budget.consume("tpa-llm", 1.0)
    assert budget.remaining("tpa-llm") == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_consume_exceeds_limit(budget):
    with pytest.raises(BudgetExceeded, match="tpa-llm"):
        await budget.consume("tpa-llm", 1.5)


@pytest.mark.asyncio
async def test_consume_no_limit(budget):
    await budget.consume("unknown", 999.0)  # no limit set, no error


@pytest.mark.asyncio
async def test_consume_accumulates(budget):
    await budget.consume("alignment", 0.2)
    await budget.consume("alignment", 0.2)
    assert budget.remaining("alignment") == pytest.approx(0.1)


@pytest.mark.asyncio
async def test_consume_accumulate_exceeds(budget):
    await budget.consume("alignment", 0.3)
    with pytest.raises(BudgetExceeded):
        await budget.consume("alignment", 0.3)


def test_set_limit():
    b = Budget()
    b.set_limit("new-det", 5.0)
    assert b.remaining("new-det") == 5.0


@pytest.mark.asyncio
async def test_concurrent_consume():
    b = Budget(daily_usd={"det": 10.0})
    await asyncio.gather(
        *[b.consume("det", 0.5) for _ in range(20)]
    )
    assert b.remaining("det") == pytest.approx(0.0)
