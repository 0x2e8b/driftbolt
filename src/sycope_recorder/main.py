"""ASGI entrypoint: this is the module gunicorn/uvicorn points at
(`sycope_recorder.main:app`).

Settings, logging, and the app are all constructed eagerly at import
time, not lazily on first request — so a bad config fails fast via
get_settings()'s SystemExit at process start, rather than surfacing on
the first incoming request.
"""

from __future__ import annotations

from sycope_recorder.api import create_app
from sycope_recorder.config import get_settings
from sycope_recorder.logging_config import setup_logging

settings = get_settings()
setup_logging(settings)
app = create_app(settings)
