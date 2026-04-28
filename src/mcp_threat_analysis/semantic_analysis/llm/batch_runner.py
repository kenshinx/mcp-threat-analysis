"""Batch runner — collects pending LLM jobs and submits via Anthropic Message Batches.

Runs as a daemon task; orchestrator can also call `flush()` for a synchronous flush.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ...common.logging import get_logger
from .client import LLMClient, LLMResponse

log = get_logger(__name__)


@dataclass(slots=True)
class BatchJob:
    detector: str
    prompt: str
    payload: str
    callback: Callable[[LLMResponse | None], Awaitable[None]]


class BatchRunner:
    def __init__(self, client: LLMClient, max_inflight: int = 32) -> None:
        self.client = client
        self.max_inflight = max_inflight
        self._queue: asyncio.Queue[BatchJob] = asyncio.Queue()
        self._sem = asyncio.Semaphore(max_inflight)
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="l3-batch-runner")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            await self._task

    async def submit(self, job: BatchJob) -> None:
        await self._queue.put(job)

    async def flush(self, timeout: float | None = None) -> None:
        async def _drain():
            while not self._queue.empty():
                await asyncio.sleep(0.05)
        await asyncio.wait_for(_drain(), timeout=timeout)

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            asyncio.create_task(self._dispatch(job))

    async def _dispatch(self, job: BatchJob) -> None:
        async with self._sem:
            try:
                resp = await self.client.call(
                    detector=job.detector,
                    prompt=job.prompt,
                    payload=job.payload,
                    mode="batch",
                )
                await job.callback(resp)
            except Exception:
                log.exception("batch.dispatch_failed", detector=job.detector)
                await job.callback(None)
