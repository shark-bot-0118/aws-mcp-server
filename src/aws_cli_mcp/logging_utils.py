"""Logging helpers for the AWS CLI MCP server."""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

from aws_cli_mcp.config import load_settings

_logging_configured = False
_logging_lock = threading.Lock()

_logger = logging.getLogger(__name__)


def configure_logging() -> None:
    """Configure structured logging for the server."""
    global _logging_configured

    settings = load_settings()
    level = getattr(logging, settings.logging.level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    handlers.append(stream_handler)

    if settings.logging.file:
        try:
            Path(settings.logging.file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(settings.logging.file)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            handlers.append(file_handler)
        except OSError as exc:
            _logger.warning("Failed to open log file %s: %s", settings.logging.file, exc)

    logging.basicConfig(level=level, handlers=handlers, force=True)

    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    if not _logging_configured:
        with _logging_lock:
            if not _logging_configured:
                configure_logging()
    return logging.getLogger(name)
