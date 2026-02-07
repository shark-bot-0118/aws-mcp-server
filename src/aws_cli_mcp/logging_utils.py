"""Logging helpers for the AWS CLI MCP server."""

from __future__ import annotations

import logging
import sys

from aws_cli_mcp.config import load_settings

_logging_configured = False


def configure_logging() -> None:
    """Configure structured logging for the server."""

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
            file_handler = logging.FileHandler(settings.logging.file)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            handlers.append(file_handler)
        except OSError as exc:
            stream_handler.handle(
                logging.LogRecord(
                    name=__name__,
                    level=logging.WARNING,
                    pathname=__file__,
                    lineno=0,
                    msg=f"Failed to open log file {settings.logging.file}: {exc}",
                    args=(),
                    exc_info=None,
                )
            )

    logging.basicConfig(level=level, handlers=handlers, force=True)

    global _logging_configured
    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    if not _logging_configured:
        configure_logging()
    return logging.getLogger(name)
