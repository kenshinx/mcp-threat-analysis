# LLM Concurrency for semantic_analysis

## Problem

The 3 LLM-based detectors (`TPALLMDetector`, `ToxicFlowDetector`,
`SchemaCodeAlignmentDetector`) iterate over tools sequentially, calling the LLM
API once per tool. The orchestrator additionally runs the 3 detectors back-to-back.
For a server with N tools, the wall-clock cost is roughly
`3 detectors × N tools × per-call latency` — fully serial.

Per-call latency on the OpenAI-compatible path (Volcengine Ark / DeepSeek /
…) is ~2–5 s with the current "rely on prompt + balanced-brace salvage" JSON
extraction. For N=3 that means ~27–45 s of LLM wall-clock per server.

## Decision

Two layers of concurrency:

1. **Tool-level**: each LLM detector fans out tools via `asyncio.gather`.
2. **Detector-level**: the orchestrator runs the 3 LLM detectors via
   `asyncio.gather` instead of `for d in detectors: await d.run(...)`.

Concurrency is bounded by a single shared `asyncio.Semaphore` **owned by
`LLMClient`** — every `client.call(...)` acquires it before issuing the
HTTP request and releases on completion. Detectors stay unaware of
concurrency; they just `await self.llm.call(...)`.

This factoring is deliberate (see "Why semaphore lives on LLMClient" below).

## Changes

### 1. `LLMClient` owns the semaphore

File: `semantic_analysis/llm/client.py`

```python
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
        self._sem = asyncio.Semaphore(
            max_concurrency if max_concurrency is not None
            else _default_concurrency(get_settings().llm_provider)
        )

    async def call(self, ...):
        # cache hit short-circuits BEFORE acquiring the semaphore
        cached = self.cache.get(detector, model, prompt, payload)
        if cached is not None:
            return ...

        async with self._sem:
            client = self._ensure_client()
            if self._provider == "anthropic":
                raw, in_tokens, out_tokens = await self._call_anthropic(...)
            else:
                raw, in_tokens, out_tokens = await self._call_openai_compatible(...)
        # post-processing (parse, budget, cache.put, log) outside the
        # semaphore so we don't hold a slot while doing local CPU work
        ...
```

Key points:
- One semaphore per `LLMClient` instance. Shared automatically across all
  detectors that share the client (the orchestrator passes the same instance
  to all 3).
- Cache lookup happens **before** semaphore acquisition. Cache hits don't
  burn a concurrency slot.
- Budget consumption and JSON parsing happen **after** semaphore release,
  to keep slots tied strictly to in-flight HTTP.
- No detector-side change required. Any future LLM call site is
  automatically rate-limited.

### 2. Detector-level concurrency in the orchestrator

File: `semantic_analysis/orchestrator.py`

Currently:

```python
for detector in self.detectors:
    findings = await detector.run(session, ctx)
    all_findings.extend(findings)
```

Change to: run rule-based detectors serially (cheap, no I/O), then run all
LLM detectors concurrently with `asyncio.gather`:

```python
rule_detectors = [d for d in self.detectors if not d.is_llm]
llm_detectors  = [d for d in self.detectors if d.is_llm]

for d in rule_detectors:
    all_findings.extend(await d.run(session, ctx))

llm_results = await asyncio.gather(
    *[d.run(session, ctx) for d in llm_detectors],
    return_exceptions=True,
)
for d, res in zip(llm_detectors, llm_results):
    if isinstance(res, Exception):
        log.warning("detector.failed", detector=d.name, err=str(res))
        continue
    all_findings.extend(res)
```

`Detector.is_llm: bool = False` is added to the base class; `TPALLMDetector`,
`ToxicFlowDetector`, `SchemaCodeAlignmentDetector` set it to `True`.

Why this is safe:
- Detector outputs are independent — each writes to a distinct
  `findings.detector` value.
- They share read-only access to `ctx.tools` and the static summary.
- They share `LLMClient` (semaphore-bounded) and `Budget` (`asyncio.Lock`-
  protected). Both are async-safe under contention.
- `findings` table writes happen **after** orchestrator collects results, in
  a single `upsert_findings` call. No write-write race.

### 3. Tool-level fan-out inside each LLM detector

`TPALLMDetector` (`detectors/tpa_llm.py`):

```python
async def run(self, session, ctx):
    tools = [t for t in ctx.tools if len((t.description or "")) >= 30]
    results = await asyncio.gather(
        *[self._analyze_tool(tool) for tool in tools],
        return_exceptions=True,
    )
    out: list[Finding] = []
    for tool, res in zip(tools, results):
        if isinstance(res, Exception):
            log.warning("tpa_llm.tool.failed", tool=tool.name, err=str(res))
            continue
        if res is not None:
            out.append(res)
    return out

async def _analyze_tool(self, tool) -> Finding | None:
    # existing per-tool body, unchanged
    ...
```

`ToxicFlowDetector` (`detectors/toxic_flow.py`):

```python
async def run(self, session, ctx):
    cap_results = await asyncio.gather(
        *[self._classify(session, tool) for tool in ctx.tools],
        return_exceptions=True,
    )
    capabilities: dict[str, list[str]] = {}
    for tool, res in zip(ctx.tools, cap_results):
        capabilities[tool.name] = [] if isinstance(res, Exception) else res
    # existing pattern-matching loop unchanged
    ...
```

`gather` preserves input order, so `zip(ctx.tools, cap_results)` is correct.

`SchemaCodeAlignmentDetector` (`detectors/schema_code_alignment.py`):

```python
async def run(self, session, ctx):
    results = await asyncio.gather(
        *[self.alignment.run_one(ctx, tool) for tool in ctx.tools],
        return_exceptions=True,
    )
    return [
        f for f in results
        if f is not None and not isinstance(f, Exception)
    ]
```

Each `gather` site uses `return_exceptions=True` and explicitly filters,
so a single tool's failure never aborts the batch. Errors are logged once
per failure.

## Why semaphore lives on `LLMClient`

Considered alternative: pass an `asyncio.Semaphore` through every detector
and `AlignmentOrchestrator` constructor, wrap each LLM call with
`async with self._sem`. Rejected because:

1. **Surface area**: 4+ classes need new constructor params and `async with`
   sites — `TPALLMDetector`, `ToxicFlowDetector`,
   `SchemaCodeAlignmentDetector`, `AlignmentOrchestrator`, plus any future
   LLM-using detector. Each is a chance to forget.
2. **Silent bypass**: a missing `async with` doesn't fail tests — it
   silently uncaps concurrency for one call site. Production hits rate
   limits before anyone notices.
3. **Test ergonomics**: detector unit tests would have to construct or
   mock a semaphore, even though they don't care about concurrency.

Putting the semaphore on `LLMClient` makes rate limiting an invariant of
the client, not a per-call-site discipline. Detectors keep their current
shape.

## Per-provider concurrency defaults

`max_concurrency` defaults vary by `MTA_LLM_PROVIDER` because real
rate limits differ by ~50× across providers:

| Provider | Default | Rationale |
|---|---|---|
| `anthropic` | **3** | Tier 1 = 50 RPM ≈ 0.83 RPS. With ~5 s/call, 3 in-flight ≈ 0.6 RPS — under the limit, with headroom for the orchestrator-level gather burst. |
| `openai_compatible` | **16** | Volcengine Ark / DeepSeek / Together typically allow ≥ 1500 RPM. 16 × 5 s ≈ 3.2 RPS is comfortably within. |

```python
def _default_concurrency(provider: str) -> int:
    if provider == "anthropic":
        return 3
    return 16  # openai_compatible
```

Override via `MTA_LLM_MAX_CONCURRENCY` (read in `common/config.py`,
plumbed into `LLMClient(max_concurrency=...)`). Set it tighter when you
hit `429`s, looser when your tier supports it.

## Concurrency control summary

- **Semaphore**: 1 per `LLMClient`, owned by the client, applied around
  every `_call_anthropic` / `_call_openai_compatible` HTTP request.
- **Cache hits** bypass the semaphore (no HTTP issued).
- **Budget** uses an `asyncio.Lock`, async-safe under contention; the
  critical section is a few microseconds (counter update), so contention
  cost is negligible against ~5 s LLM calls.
- **`LLMCache`** is process-local dict, async-safe per key. Two coroutines
  with identical `(detector, model, prompt, payload)` may both miss and
  issue duplicate calls — a wasted call but not a correctness bug. In
  practice each tool produces a unique payload so this almost never fires.
- **Orchestrator-level gather** runs the 3 LLM detectors in parallel; their
  in-flight calls share the single client semaphore, so the global cap is
  still respected (a 3-tool, 3-detector burst peaks at 9 in-flight,
  bounded by `max_concurrency`).

## Error handling

Every `asyncio.gather` site uses `return_exceptions=True` and filters:

- Tool-level (inside detectors): one tool's failure → that tool contributes
  no finding; sibling tools continue. Logged at WARN with `tool` + `err`.
- Detector-level (in orchestrator): one detector's complete failure → that
  detector contributes no findings; sibling detectors continue. Logged at
  WARN with `detector` + `err`.

No exception ever propagates out of `gather` — the orchestrator always
returns a `SemanticAnalysisResult`, possibly with reduced detector
coverage. Aggregate failure (every detector throws) is logged but does
not raise; the orchestrator currently has no "all-LLM-failed" semantic
and changing that is out of scope.

## Expected speedup

For a typical MCP server with 3 tools, 3 LLM detectors, ~5 s per LLM
call:

| | Before | Tool-only gather | Tool + detector gather |
|---|---|---|---|
| LLM calls | 9 serial | 3 batches × 3 parallel | 1 burst of 9 (capped at semaphore) |
| Wall-clock | ~45 s | ~15 s | ~5–10 s |
| Speedup vs baseline | — | ~3× | **~5–9×** |

The tool+detector combined number assumes `max_concurrency ≥ 9` so all 9
calls go in one wave. With `anthropic` default of 3, expect ~15 s
(3 waves of 3); with `openai_compatible` default of 16, expect ~5 s.

For high-tool-count servers (N=10+), the tool-level fan-out dominates
the win and the detector-level gather contributes a fixed ~3× factor on
top.

## Not in scope

- Merging `TPALLMDetector` + `ToxicFlowDetector` into a single prompt
  (single-detector batching across tools) — bigger win for high-N
  servers but requires prompt design work.
- Using the `BatchRunner` daemon — it targets cross-server batching with
  a different lifecycle.
- Switching OpenAI-compatible path to `response_format=json_object` —
  orthogonal latency win, deserves its own spec.
- Streaming responses — would complicate the JSON salvage logic.

## Test plan

- Unit: `LLMClient` honors `max_concurrency` (assert ≤ N coroutines hold
  the semaphore at any time, using a fake client that records timestamps).
- Unit: each detector survives one-tool exceptions without aborting siblings.
- Integration: timing log on `mta-semantic` for a fixture with ≥ 3 tools,
  before/after, asserting wall-clock drops in line with the table above.
- Regression: existing fixture-based tests — recall on
  `prompt_injection_ts`, `schema_mismatch_ts`, `toxic_flow_ts` must not
  decrease.
