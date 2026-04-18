"""Structured logging configuration for QVis.

Import and call configure_logging() once at application startup
before any other imports that use logging.
"""
import logging
import sys

import structlog


def _chain_processors(*processors):
    """Chain multiple structlog processors into a single callable.

    ProcessorFormatter.processor is called as processor(logger, method_name, event_dict).
    This helper applies each processor in order, passing the result through.
    """
    def chained(logger, method_name, event_dict):
        for proc in processors:
            result = proc(logger, method_name, event_dict)
            if isinstance(result, str):
                return result
            event_dict = result
        return event_dict
    return chained


def configure_logging(log_level: str = "INFO", log_format: str = "console") -> None:
    """Configure structlog for the entire application.

    In development (log_format='console'): human-readable colored output.
    In production (log_format='json'): JSON lines for log aggregation.

    Args:
        log_level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format — 'console' or 'json'.
    """
    # Map string level to Python logging constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(log_level.upper(), logging.INFO)

    # Shared processors for both renderers
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Exception renderer converts exc_info=True into a formatted 'exception' string
    exception_renderer = structlog.processors.ExceptionRenderer()

    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            exception_renderer,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Chain exception renderer before the final renderer so that
    # exc_info=True produces a formatted 'exception' field in the output.
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=_chain_processors(exception_renderer, renderer),
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level)

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
