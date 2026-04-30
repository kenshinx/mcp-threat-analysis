# LLM Tool-Level Concurrency for semantic_analysis

## Problem

The 3 LLM-based detectors (`TPALLMDetector`, `ToxicFlowDetector`, `SchemaCodeAlignmentDetector`) iterate over tools sequentially, calling the LLM API once per tool. For a server with N tools, each detector makes N serial API calls (~2-5s each). Total wall-clock for 3 detectors x N tools is dominated by serial LLM latency.

## Decision

Add tool-level concurrency inside each LLM detector. Orchestrator remains serial (detector A, then B, then C). No detector merging.

## Changes

### 1. `SemanticAnalysisConfig` — add concurrency param

File: `semantic_analysis/orchestrator.py`

Add `max_llm_concurrency: int = 8` to `SemanticAnalysisConfig`. Orchestrator creates an `asyncio.Semaphore` from this value and passes it to LLM detectors that accept it.

### 2. Detector base — optional semaphore

File: `semantic_analysis/detectors/base.py`

No change needed. Semaphore is passed through constructor on each detector that uses LLM.

### 3. `TPALLMDetector` — tool gather

File: `semantic_analysis/detectors/tpa_llm.py`

Before:
```python
for tool in ctx.tools:
    resp = await self.llm.call(...)
```

After:
```python
coros = [self._analyze_tool(tool) for tool in ctx.tools if len(tool.description or "") >= 30]
results = await asyncio.gather(*coros)
out = [f for f in results if f is not None]
```

Each `_analyze_tool` wraps the existing LLM call + Finding construction in `async with self._sem`, and catches exceptions (log + return None).

### 4. `ToxicFlowDetector` — tool gather

File: `semantic_analysis/detectors/toxic_flow.py`

Before:
```python
for tool in ctx.tools:
    caps = await self._classify(session, tool)
```

After:
```python
cap_results = await asyncio.gather(*[
    self._classify(session, tool) for tool in ctx.tools
])
capabilities = dict(zip([t.name for t in ctx.tools], cap_results))
```

`_classify` already handles exceptions internally (returns `[]`). Add `async with self._sem` around the LLM call inside `_classify`.

### 5. `SchemaCodeAlignmentDetector` — tool gather

File: `semantic_analysis/detectors/schema_code_alignment.py`

Before:
```python
for tool in ctx.tools:
    f = await self.alignment.run_one(ctx, tool)
```

After:
```python
results = await asyncio.gather(*[
    self.alignment.run_one(ctx, tool) for tool in ctx.tools
])
out = [f for f in results if f is not None]
```

`alignment.run_one` already returns `Finding | None` and handles exceptions. Add `async with self._sem` around the LLM call in `AlignmentOrchestrator.run_one`.

### 6. Semaphore threading

Each LLM detector accepts `semaphore: asyncio.Semaphore | None = None` in `__init__`. When `None`, no concurrency limit is applied (backward compatible for tests). Orchestrator passes the shared semaphore to all 3 detectors.

## Concurrency control

- Single `asyncio.Semaphore(max_llm_concurrency)` shared across all 3 detectors
- Default `max_llm_concurrency = 8` — safe for most OpenAI-compatible endpoints
- Each LLM `call()` acquires `sem` before request, releases after
- Budget and cache are already async-safe (`Budget` uses `asyncio.Lock`, `LLMCache` is process-local dict with no shared mutation per key)

## Error handling

- Per-tool failures are isolated: exception caught inside coroutine, logged, returns `None` or `[]`
- `asyncio.gather` does NOT use `return_exceptions=True` — exceptions are caught inside each coroutine wrapper instead, so we control the return type

## Expected speedup

For a typical MCP server with 3 tools, 3 LLM detectors:

| | Before | After |
|---|---|---|
| LLM calls | 9 serial | 3 parallel batches of 3 |
| Wall-clock | ~27-45s | ~9-15s |
| Speedup | — | ~3x |

## Not in scope

- Detector-level parallelism (orchestrator stays serial)
- Merging TPALLMDetector + ToxicFlowDetector into one call
- Using the existing `BatchRunner` daemon (it's designed for a different lifecycle)
