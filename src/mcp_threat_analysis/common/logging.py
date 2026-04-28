"""Structured logging via structlog, JSON output."""
from __future__ import annotations

import logging
import sys

import structlog


def _configure_once() -> None:
    if getattr(_configure_once, "_done", False):
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stderr,
    )
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )
    _configure_once._done = True  # type: ignore[attr-defined]


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    _configure_once()
    return structlog.get_logger(name)
