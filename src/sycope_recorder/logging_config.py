"""Configures root logging (text or JSON) and funnels uvicorn/gunicorn
logs through the same handler so container/journal output has one
consistent format regardless of which component emitted the line.
"""

from __future__ import annotations

import json
import logging
import sys

from sycope_recorder.config import Settings

_TEXT_FMT = "%(asctime)s [%(levelname)s] %(message)s"


class _JsonFormatter(logging.Formatter):
    """Formats log records as JSON, safely encoding the message.

    Building the JSON string via json.dumps (rather than interpolating
    %(message)s directly into a hand-written JSON template) ensures the
    output is always valid JSON, even if the message contains quotes,
    newlines, or backslashes.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload)


def setup_logging(settings: Settings) -> None:
    """Set up the root logger's handler/formatter and rewire uvicorn/gunicorn
    to use it instead of their own.

    Existing root handlers are cleared first so this is safe to call more
    than once (e.g. re-invoked in tests) without stacking duplicate
    handlers and duplicating every log line. uvicorn/gunicorn loggers are
    then stripped of their own handlers and left to propagate, so every
    log line — ours and theirs — goes through the one handler/formatter
    configured here instead of each library formatting independently.
    """
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    formatter: logging.Formatter
    if settings.log_format == "json":
        formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(_TEXT_FMT)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())

    # Route uvicorn/gunicorn logs through the same handler; drop access spam.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error", "gunicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
