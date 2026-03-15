"""Shared helpers for script CLI entrypoints."""

from __future__ import annotations

import logging
from collections.abc import Callable


def get_logger_with_fallback(name: str) -> logging.Logger:
    """Return centralized logger if available, otherwise stdlib fallback logger."""
    try:
        from src.utils.logging_config import get_logger

        return get_logger(name)
    except Exception:
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)


def run_cli(action: Callable[[], int | None], logger: logging.Logger, error_message: str) -> int:
    """Execute CLI action and return process-style status code."""
    try:
        result = action()
        return 0 if result is None else int(result)
    except Exception:
        logger.exception(error_message)
        return 1
