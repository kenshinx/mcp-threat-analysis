"""Encoder shim. By default uses a deterministic hash-based pseudo-embedding
so the rest of the pipeline can be exercised without external API calls.
Swap in OpenAI / Voyage by setting MTA_EMBEDDING_PROVIDER=openai.
"""
from __future__ import annotations

import hashlib
import os

from ...common.config import get_settings


class EmbeddingEncoder:
    def __init__(self) -> None:
        self.provider = os.getenv("MTA_EMBEDDING_PROVIDER", "hash")
        self.dim = get_settings().embedding_dim

    async def encode(self, text: str) -> list[float]:
        if self.provider == "openai":
            return await self._openai(text)
        return self._hash(text)

    def _hash(self, text: str) -> list[float]:
        # Deterministic, length = dim. Distribute hash bytes into floats.
        out: list[float] = []
        seed = text.encode("utf-8")
        for i in range(self.dim):
            h = hashlib.sha256(seed + i.to_bytes(4, "little")).digest()
            # Use first 4 bytes → unsigned int → normalize.
            v = int.from_bytes(h[:4], "little")
            out.append((v / 0xFFFFFFFF) * 2.0 - 1.0)
        # L2 normalize so cosine = dot product.
        n = sum(x * x for x in out) ** 0.5 or 1.0
        return [x / n for x in out]

    async def _openai(self, text: str) -> list[float]:
        try:
            from openai import AsyncOpenAI  # type: ignore
        except ImportError as e:
            raise RuntimeError("openai SDK not installed") from e
        client = AsyncOpenAI()
        resp = await client.embeddings.create(
            model=get_settings().embedding_model, input=text
        )
        return resp.data[0].embedding
