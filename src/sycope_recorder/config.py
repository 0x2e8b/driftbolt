"""Process-wide configuration: env-driven Settings and its loader.

All runtime configuration is read once at import time in main.py via
get_settings(), which either returns a validated Settings instance or exits
the process with an ops-readable error. There is no config reload — values
are fixed for the life of the process.
"""

from __future__ import annotations

import sys

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# BPF filter modes accepted by npcapextract; default_filter falls back to
# "full" (see _known_filter) if it isn't one of these.
VALID_FILTER_MODES: frozenset[str] = frozenset(
    {"full", "hosts", "client", "server", "port"}
)


class Settings(BaseSettings):
    """App configuration, populated from SR_-prefixed environment variables.

    Each field maps to an env var of the same name uppercased with an SR_
    prefix (e.g. `public_host` <- `SR_PUBLIC_HOST`); unrecognized env vars
    are ignored rather than rejected. `public_host` is the only required
    field — everything else has a legacy-compatible default.
    """

    model_config = SettingsConfigDict(env_prefix="SR_", env_file=None, extra="ignore")

    public_host: str
    download_prefix: str = "downloads"
    timeline_dir: str = "/storage/pcaps/rolling"
    output_dir: str = "/storage/pcaps/alerts"
    default_filter: str = "full"
    default_before: int = 360
    default_after: int = 360
    max_concurrent_extractions: int = 1
    extract_timeout_seconds: int = 300
    npcapextract_path: str = "npcapextract"
    retention_max_age_days: int = 7
    retention_max_total_bytes: int = 0
    retention_interval_seconds: int = 3600
    log_level: str = "INFO"
    log_format: str = "text"

    @field_validator("max_concurrent_extractions")
    @classmethod
    def _min_one(cls, v: int) -> int:
        """Clamp to at least 1 instead of raising, matching the legacy config
        loader's "safety net" defaulting (see SPEC.md §7) — a misconfigured
        0/negative value should degrade to serialized extraction, not take
        the whole service down at startup."""
        return max(1, v)

    @field_validator("default_filter")
    @classmethod
    def _known_filter(cls, v: str) -> str:
        """Fall back to "full" for an unrecognized mode instead of raising,
        matching the legacy config loader's defaulting behavior (see
        SPEC.md §8) — an unknown filter should widen to "no filtering"
        rather than block startup."""
        return v if v in VALID_FILTER_MODES else "full"


def get_settings() -> Settings:
    """Build Settings, or exit the process with a clean stderr message.

    This runs at import time in main.py, before logging or anything else is
    set up — an unhandled pydantic ValidationError there would surface as a
    raw traceback with no operational context. Converting it to a one-line
    stderr message and SystemExit(1) gives ops a readable reason (e.g.
    missing SR_PUBLIC_HOST) instead of a stack trace to decipher.
    """
    try:
        return Settings()
    except Exception as exc:  # pragma: no cover - exercised at process start
        print(f"ERROR: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
