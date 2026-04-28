"""Prompt loader. Reads markdown files relative to this package."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


@lru_cache
def load_prompt(name: str) -> str:
    p = _PROMPTS_DIR / name
    return p.read_text(encoding="utf-8")
