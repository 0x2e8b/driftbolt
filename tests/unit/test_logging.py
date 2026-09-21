import io
import json
import logging

from sycope_recorder.config import Settings
from sycope_recorder.logging_config import setup_logging


def test_setup_logging_sets_level_and_handler():
    s = Settings(public_host="h", log_level="WARNING")
    setup_logging(s)
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert root.handlers  # at least one handler installed


def test_setup_logging_is_idempotent():
    s = Settings(public_host="h", log_level="INFO")
    setup_logging(s)
    setup_logging(s)
    assert len(logging.getLogger().handlers) == 1


def test_json_format_produces_valid_json_with_special_characters():
    s = Settings(public_host="h", log_level="INFO", log_format="json")
    setup_logging(s)
    root = logging.getLogger()

    stream = io.StringIO()
    # Swap the stdout stream handler's stream so we can capture the exact
    # formatted output without relying on caplog (which bypasses formatters).
    handler = root.handlers[0]
    handler.stream = stream

    message = 'value with "quotes"\nand a newline and a backslash \\'
    root.info(message)

    line = stream.getvalue().strip()
    parsed = json.loads(line)  # must not raise: output must be valid JSON
    assert parsed["message"] == message
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "root"
    assert "time" in parsed
