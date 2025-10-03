"""Shared logging utilities for Kong Guard AI services."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

METRICS_LOGGER_NAME = "kong_guard_ai.metrics"


class ServiceContextFilter(logging.Filter):
    """Inject a static service name into every log record."""

    def __init__(self, service_name: str | None):
        super().__init__()
        self._service_name = service_name

    def filter(self, record: logging.LogRecord) -> bool:
        if self._service_name and not hasattr(record, "service_name"):
            record.service_name = self._service_name
        return True


class JsonFormatter(logging.Formatter):
    """Formatter that outputs log records as JSON strings."""

    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        optional_fields = (
            "event",
            "service",
            "service_name",
            "metrics",
            "threat_event",
            "extra_data",
        )

        for field in optional_fields:
            value = getattr(record, field, None)
            if value is not None:
                log_record[field] = value

        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_record, default=str)


def _should_enable_file_logging() -> bool:
    flag = os.getenv("ENABLE_FILE_LOGGING", "1").lower()
    return flag not in {"0", "false", "no", "off"}


def setup_logging(service_name: str | None = None) -> logging.Logger:
    """Configure console and file logging, returning the metrics logger."""

    root_logger = logging.getLogger()
    if getattr(root_logger, "_kong_guard_logging_configured", False):
        return logging.getLogger(METRICS_LOGGER_NAME)

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    root_logger.setLevel(log_level)

    # Reset existing handlers to avoid duplicate outputs when reloading
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    json_formatter = JsonFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(json_formatter)
    root_logger.addHandler(console_handler)

    metrics_logger = logging.getLogger(METRICS_LOGGER_NAME)
    metrics_logger.setLevel(log_level)

    if _should_enable_file_logging():
        log_dir = Path(os.getenv("LOG_DIR", "/app/logs"))
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            metrics_path = log_dir / "metrics.log"

            # Avoid duplicate handlers when running under reloaders
            if not any(isinstance(h, RotatingFileHandler) for h in metrics_logger.handlers):
                file_handler = RotatingFileHandler(
                    metrics_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
                )
                file_handler.setFormatter(json_formatter)
                metrics_logger.addHandler(file_handler)
        except Exception as exc:  # pragma: no cover - logging fallback
            root_logger.warning("Failed to configure file logging at %s: %s", log_dir, exc)

            fallback_dir = Path("./logs")
            if fallback_dir != log_dir:
                try:
                    fallback_dir.mkdir(parents=True, exist_ok=True)
                    metrics_path = fallback_dir / "metrics.log"
                    if not any(isinstance(h, RotatingFileHandler) for h in metrics_logger.handlers):
                        file_handler = RotatingFileHandler(
                            metrics_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
                        )
                        file_handler.setFormatter(json_formatter)
                        metrics_logger.addHandler(file_handler)
                except Exception as fallback_exc:  # pragma: no cover - logging fallback
                    root_logger.warning("Failed fallback file logging at %s: %s", fallback_dir, fallback_exc)

    if service_name:
        context_filter = ServiceContextFilter(service_name)
        console_handler.addFilter(context_filter)
        metrics_logger.addFilter(context_filter)

    root_logger._kong_guard_logging_configured = True

    return metrics_logger


def get_metrics_logger() -> logging.Logger:
    """Return the shared metrics logger instance."""

    return logging.getLogger(METRICS_LOGGER_NAME)
