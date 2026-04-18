"""Comprehensive tests for QVis structured logging (structlog) system.

Validates:
  - configure_logging() produces correct configuration for both console and JSON formats
  - Log level mapping is accurate
  - Third-party loggers are silenced appropriately
  - All backend modules use structlog (no bare print/logging)
  - Structured log events contain expected keys (event, level, timestamp, etc.)
  - Request ID context variable propagation
  - Settings integration (log_level, log_format)
"""

import io
import json
import logging
import os
import sys
from unittest.mock import patch

import pytest
import structlog

from backend.logging_config import configure_logging
from backend.config import Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _capture_logs(log_level: str = "INFO", log_format: str = "console"):
    """Configure structlog with a StringIO sink and return the captured text."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)

    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(log_level.upper(), logging.INFO)

    # Configure structlog which sets up ProcessorFormatter on the root handler
    configure_logging(log_level=log_level, log_format=log_format)

    # Copy the ProcessorFormatter from the handler configure_logging installed
    root = logging.getLogger()
    if root.handlers and root.handlers[0].formatter:
        handler.setFormatter(root.handlers[0].formatter)

    # Replace the root handler with our StringIO handler (with the correct formatter)
    root.handlers = [handler]
    root.setLevel(level)

    return buf


def _reset_logging():
    """Reset structlog and logging to a clean state."""
    structlog.reset_defaults()
    # Clear the root logger handlers
    root = logging.getLogger()
    root.handlers = []


# ---------------------------------------------------------------------------
# Tests: configure_logging
# ---------------------------------------------------------------------------

class TestConfigureLogging:
    """Tests for the configure_logging() function."""

    def teardown_method(self):
        _reset_logging()

    def test_default_configuration(self):
        """configure_logging() should succeed with default parameters."""
        configure_logging()
        # After configuration, getting a logger should not raise
        logger = structlog.get_logger("test_default")
        assert logger is not None

    def test_console_format(self):
        """Console format should produce human-readable output."""
        buf = _capture_logs(log_format="console")
        logger = structlog.get_logger("test_console")
        logger.info("test_event", key="value")

        output = buf.getvalue()
        assert "test_event" in output
        assert "key" in output
        assert "value" in output

    def test_json_format(self):
        """JSON format should produce parseable JSON lines."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("test_json")
        logger.info("json_test_event", severity="high", count=42)

        output = buf.getvalue().strip()
        # Should be valid JSON
        parsed = json.loads(output)
        assert parsed["event"] == "json_test_event"
        assert parsed["severity"] == "high"
        assert parsed["count"] == 42

    def test_json_contains_iso_timestamp(self):
        """JSON logs should contain an ISO-8601 timestamp."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("test_timestamp")
        logger.info("ts_check")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert "timestamp" in parsed
        # ISO format: 2024-01-15T10:30:00...
        assert "T" in parsed["timestamp"]

    def test_json_contains_log_level(self):
        """JSON logs should include the log level."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("test_level")
        logger.warning("level_check")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["level"] == "warning"

    def test_json_contains_logger_name(self):
        """JSON logs should include the logger name."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("my_named_logger")
        logger.info("name_check")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert "my_named_logger" in parsed.get("logger", "") or "name" in parsed

    def test_debug_level_captures_debug_messages(self):
        """DEBUG level should capture debug and above messages."""
        buf = _capture_logs(log_level="DEBUG")
        logger = structlog.get_logger("test_debug")
        logger.debug("debug_msg")

        output = buf.getvalue()
        assert "debug_msg" in output

    def test_info_level_filters_debug_messages(self):
        """INFO level should NOT capture debug messages."""
        buf = _capture_logs(log_level="INFO")
        logger = structlog.get_logger("test_info_filter")
        logger.debug("should_not_appear")
        logger.info("should_appear")

        output = buf.getvalue()
        assert "should_appear" in output
        assert "should_not_appear" not in output

    def test_warning_level_filters_info_messages(self):
        """WARNING level should NOT capture info messages but should capture warnings."""
        buf = _capture_logs(log_level="WARNING")
        logger = structlog.get_logger("test_warn_filter")
        logger.info("info_should_not_appear")
        logger.warning("warn_should_appear")

        output = buf.getvalue()
        assert "warn_should_appear" in output
        assert "info_should_not_appear" not in output

    def test_error_level_captures_only_errors_and_above(self):
        """ERROR level should capture errors but not info/warning."""
        buf = _capture_logs(log_level="ERROR")
        logger = structlog.get_logger("test_error_filter")
        logger.info("info_hidden")
        logger.warning("warn_hidden")
        logger.error("error_visible")

        output = buf.getvalue()
        assert "error_visible" in output
        assert "info_hidden" not in output
        assert "warn_hidden" not in output

    def test_invalid_level_defaults_to_info(self):
        """An invalid log level string should gracefully default to INFO."""
        configure_logging(log_level="INVALID_LEVEL")
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_uvicorn_access_silenced(self):
        """uvicorn.access logger should be set to WARNING level."""
        configure_logging(log_level="DEBUG")
        uvicorn_logger = logging.getLogger("uvicorn.access")
        assert uvicorn_logger.level >= logging.WARNING

    def test_aiosqlite_silenced(self):
        """aiosqlite logger should be set to WARNING level."""
        configure_logging(log_level="DEBUG")
        aiosqlite_logger = logging.getLogger("aiosqlite")
        assert aiosqlite_logger.level >= logging.WARNING


# ---------------------------------------------------------------------------
# Tests: Settings integration
# ---------------------------------------------------------------------------

class TestSettingsIntegration:
    """Tests that Settings correctly exposes logging configuration."""

    def test_settings_has_log_level(self):
        """Settings should have a log_level field with default 'INFO'."""
        s = Settings(_env_file=None)
        assert s.log_level == "INFO"

    def test_settings_has_log_format(self):
        """Settings should have a log_format field with default 'console'."""
        s = Settings(_env_file=None)
        assert s.log_format == "console"

    def test_settings_log_level_from_env(self):
        """Settings should read LOG_LEVEL from environment."""
        os.environ["LOG_LEVEL"] = "DEBUG"
        try:
            s = Settings(_env_file=None)
            assert s.log_level == "DEBUG"
        finally:
            del os.environ["LOG_LEVEL"]

    def test_settings_log_format_from_env(self):
        """Settings should read LOG_FORMAT from environment."""
        os.environ["LOG_FORMAT"] = "json"
        try:
            s = Settings(_env_file=None)
            assert s.log_format == "json"
        finally:
            del os.environ["LOG_FORMAT"]


# ---------------------------------------------------------------------------
# Tests: No bare print/logging in backend
# ---------------------------------------------------------------------------

class TestNoBarePrintOrLogging:
    """Verify no bare print() or stdlib logging calls remain in backend code."""

    def test_no_print_in_backend(self):
        """No Python file in backend/ should contain bare print() calls."""
        import subprocess
        result = subprocess.run(
            ["rg", r"\bprint\s*\(", "backend/", "--files-with-matches"],
            capture_output=True, text=True, cwd="/home/z/my-project/qvis"
        )
        # Empty output means no matches
        assert result.returncode != 0 or result.stdout.strip() == "", (
            f"Bare print() found in: {result.stdout.strip()}"
        )

    def test_no_stdlib_logging_in_backend(self):
        """No backend module should use stdlib logging.getLogger() directly."""
        import subprocess
        # Exclude logging_config.py itself which legitimately imports logging
        result = subprocess.run(
            ["rg", r"import logging", "backend/", "--files-with-matches", "-g", "!logging_config.py"],
            capture_output=True, text=True, cwd="/home/z/my-project/qvis"
        )
        assert result.returncode != 0 or result.stdout.strip() == "", (
            f"import logging found in: {result.stdout.strip()}"
        )

    def test_no_logger_equals_logging_getlogger(self):
        """No backend module should use logger = logging.getLogger()."""
        import subprocess
        result = subprocess.run(
            ["rg", r"logging\.getLogger", "backend/", "--files-with-matches", "-g", "!logging_config.py"],
            capture_output=True, text=True, cwd="/home/z/my-project/qvis"
        )
        assert result.returncode != 0 or result.stdout.strip() == "", (
            f"logging.getLogger() found in: {result.stdout.strip()}"
        )


# ---------------------------------------------------------------------------
# Tests: Structured log events contain expected keys
# ---------------------------------------------------------------------------

class TestStructuredLogEvents:
    """Verify that structured log events contain the expected keys."""

    def test_json_log_event_has_required_keys(self):
        """JSON formatted logs must contain event, level, and timestamp."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("test_keys")
        logger.info("threat_detected", technique_id="QTT001", severity="high")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert "event" in parsed
        assert "level" in parsed
        assert "timestamp" in parsed
        assert parsed["event"] == "threat_detected"
        assert parsed["technique_id"] == "QTT001"
        assert parsed["severity"] == "high"

    def test_console_log_contains_event_name(self):
        """Console formatted logs should contain the event name."""
        buf = _capture_logs(log_format="console")
        logger = structlog.get_logger("test_console_event")
        logger.warning("anomaly_detected", z_score=4.2)

        output = buf.getvalue()
        assert "anomaly_detected" in output

    def test_exc_info_included(self):
        """Log entries with exc_info=True should include exception info."""
        buf = _capture_logs(log_format="json")
        logger = structlog.get_logger("test_exc")
        try:
            raise ValueError("test exception")
        except ValueError:
            logger.error("test_error_with_exc", exc_info=True)

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["event"] == "test_error_with_exc"
        # exc_info should be in the output (either as field or in message)
        assert "exception" in parsed or "ValueError" in json.dumps(parsed)


# ---------------------------------------------------------------------------
# Tests: Request ID context variable propagation
# ---------------------------------------------------------------------------

class TestRequestIDPropagation:
    """Test that structlog contextvars correctly propagate request IDs."""

    def teardown_method(self):
        structlog.contextvars.clear_contextvars()
        _reset_logging()

    def test_request_id_bound_to_context(self):
        """Binding request_id to contextvars should appear in log output."""
        buf = _capture_logs(log_format="json")
        structlog.contextvars.bind_contextvars(request_id="abc123")

        logger = structlog.get_logger("test_request_id")
        logger.info("request_bound_test")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed.get("request_id") == "abc123"

    def test_request_id_cleared_between_contexts(self):
        """Clearing contextvars should remove request_id from subsequent logs."""
        buf = _capture_logs(log_format="json")
        structlog.contextvars.bind_contextvars(request_id="first")
        logger = structlog.get_logger("test_clear")

        logger.info("with_id")
        first_output = buf.getvalue().strip()

        structlog.contextvars.clear_contextvars()
        logger.info("without_id")
        full_output = buf.getvalue()
        lines = [l for l in full_output.strip().split("\n") if l.strip()]

        first_parsed = json.loads(lines[0])
        second_parsed = json.loads(lines[1])
        assert first_parsed.get("request_id") == "first"
        assert "request_id" not in second_parsed


# ---------------------------------------------------------------------------
# Tests: Module-level logger consistency
# ---------------------------------------------------------------------------

class TestModuleLoggerConsistency:
    """Verify that all backend modules use structlog correctly."""

    def test_analyzer_uses_structlog(self):
        """backend.threat_engine.analyzer should use structlog."""
        from backend.threat_engine import analyzer
        assert hasattr(analyzer, "logger")
        # Verify it's a structlog bound logger
        log = analyzer.logger
        # structlog bound loggers have an info method
        assert callable(getattr(log, "info", None))

    def test_main_uses_structlog(self):
        """backend.main should use structlog."""
        import backend.main as main_mod
        assert hasattr(main_mod, "logger")
        log = main_mod.logger
        assert callable(getattr(log, "info", None))

    def test_websocket_uses_structlog(self):
        """backend.api.websocket should use structlog."""
        import backend.api.websocket as ws_mod
        assert hasattr(ws_mod, "logger")
        log = ws_mod.logger
        assert callable(getattr(log, "info", None))

    def test_all_backend_modules_importable_with_structlog(self):
        """All backend modules should be importable without stdlib logging errors."""
        modules = [
            "backend.config",
            "backend.logging_config",
            "backend.metrics",
            "backend.storage.database",
            "backend.threat_engine.models",
            "backend.threat_engine.rules",
            "backend.threat_engine.analyzer",
            "backend.threat_engine.correlator",
            "backend.threat_engine.baseline",
            "backend.api.websocket",
            "backend.api.auth",
            "backend.api.ratelimit",
            "backend.api.security_headers",
            "backend.collectors.mock",
            "backend.collectors.scenario",
            "backend.collectors.aggregator",
        ]
        for mod_name in modules:
            __import__(mod_name)


# ---------------------------------------------------------------------------
# Tests: Specific log event names
# ---------------------------------------------------------------------------

class TestLogEventNames:
    """Verify that expected structured log event names are used in the codebase."""

    EXPECTED_EVENTS = [
        "threat_detected",
        "rule_executed",
        "simulation_loop_start",
        "simulation_loop_complete",
        "simulation_loop_error",
        "collection_complete",
        "collection_failed",
        "websocket_connected",
        "websocket_disconnected",
        "baseline_anomalies_detected",
        "campaigns_detected",
        "threats_persisted",
        "threats_resolved",
        "calibration_saved",
        "calibration_complete",
    ]

    @pytest.mark.parametrize("event_name", EXPECTED_EVENTS)
    def test_event_name_in_codebase(self, event_name):
        """Each expected event name should appear as a string literal in backend code."""
        import subprocess
        result = subprocess.run(
            ["rg", f'"{event_name}"', "backend/", "--files-with-matches"],
            capture_output=True, text=True, cwd="/home/z/my-project/qvis"
        )
        assert result.returncode == 0 and result.stdout.strip() != "", (
            f"Event '{event_name}' not found in backend code"
        )
