"""Persistent structlog configuration — tees agent events to a JSON-line log file.

Call setup_logging() once at CLI entry before pipeline execution.
Stdout keeps human-readable ConsoleRenderer; the log file gets JSONRenderer
(one JSON object per line, grep/jq friendly).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

import structlog


def setup_logging(log_file: str | None = None) -> str:
    """Configure structlog + stdlib to tee structured events to *log_file*.

    Returns the resolved log file path.
    Safe to call once per process; subsequent calls are no-ops (structlog is
    already configured after the first call due to cache_logger_on_first_use).
    """
    if log_file is None:
        log_file = os.environ.get("CRYPTODEP_LOG_FILE") or _default_log_path()

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers if called more than once (e.g. test suites).
    existing_files = {
        h.baseFilename for h in root.handlers if isinstance(h, logging.FileHandler)
    }
    if log_file not in existing_files:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processors=[
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
            )
        )
        root.addHandler(file_handler)

    # Only configure structlog once; if it's been configured (e.g. in tests) skip.
    if not getattr(structlog, "_cryptodep_configured", False):
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        # Console (stdout) stays human-readable.
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                processors=[
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.dev.ConsoleRenderer(),
                ],
            )
        )
        root.addHandler(console_handler)
        structlog._cryptodep_configured = True  # type: ignore[attr-defined]

    return log_file


def _default_log_path() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(Path("logs") / f"cryptodep_{ts}.log")
