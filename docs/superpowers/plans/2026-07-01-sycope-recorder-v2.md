# Sycope Traffic Recorder v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-implement the Sycope alert → PCAP-extract → serve pipeline as a containerized FastAPI service behind Caddy, preserving the legacy `/extract` request/response contract while modernizing infrastructure.

**Architecture:** A Docker Compose stack of two services: `caddy` (HTTPS edge via internal CA; Basic auth + IP allowlist; serves extracted PCAPs as static files; reverse-proxies the API over a unix socket) and `api` (a FastAPI app run by gunicorn with a single uvicorn worker, which parses Sycope alerts, shells out to `npcapextract`, and runs a background retention sweep). A future `recorder` (n2disk) container attaches to the same volumes without redesign.

**Tech Stack:** Python 3.12+, uv (env + lockfile), FastAPI, gunicorn + uvicorn worker, pydantic / pydantic-settings, Caddy, Docker Compose, pytest (+ pytest-asyncio, httpx), ruff.

**Reference documents:**
- Behavioral contract of the legacy system: `SPEC.md` (sections cited as "SPEC §N").
- Approved v2 design: `docs/superpowers/specs/2026-07-01-sycope-recorder-v2-design.md`.

## Global Constraints

Every task's requirements implicitly include this section.

- **Python floor:** 3.12+. Use timezone-aware datetime APIs (never `datetime.utcfromtimestamp`).
- **Env/tooling:** the project is managed by `uv`; all commands run via `uv run ...`; dependencies are declared in `pyproject.toml` and locked in `uv.lock`.
- **Runtime dependencies (only these):** `fastapi`, `uvicorn[standard]`, `gunicorn`, `pydantic`, `pydantic-settings`. **Dev group:** `pytest`, `pytest-asyncio`, `httpx`, `ruff`.
- **Process model:** exactly **1** gunicorn worker (uvicorn worker class). The extraction concurrency gate and the retention task rely on this single-worker assumption.
- **Contract preservation (copy exactly from SPEC):** alert field-alias parsing (§5.3), BPF construction (§5.5), `npcapextract` invocation `-t -b -e -f -o` with timestamp format `%Y-%m-%d %H:%M:%S` and a 300 s default timeout (§3.2/§5.4), filename scheme `{alert_time:%Y%m%d_%H%M%S}_{safe_id}.pcap` with id sanitization (alnum + `-`/`_`, 64-char cap, `"alert"` fallback) (§5.4), and all post-validation `/extract` outcomes returning **HTTP 200** with an `X-Result` header and body ∈ { download URL, `NO BPF FILTER`, `ERROR: npcapextract timeout`, `ERROR: npcapextract failed` } (§5.2).
- **Documented divergences (do NOT reproduce legacy here):** returned URL is `https://{public_host}/{download_prefix}/{filename}`; auth + IP allowlist live in Caddy, not the app; config is pydantic-settings (env + optional file), not `config.json`; a zero-match ("MISS") still returns `ERROR: npcapextract failed` to the caller but is logged distinctly server-side; `500` returns a generic body (detail logged, never leaked); non-numeric `Content-Length` returns a clean `400`.
- **Time budget knob:** `extract_timeout_seconds` (default 300); the gunicorn worker timeout must exceed it (set to 330).
- **Commit discipline:** commit at the end of every task with the shown message.

---

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml`, `uv.lock` | Project metadata, deps (runtime + dev group), tool config (ruff, pytest) |
| `src/sycope_recorder/__init__.py` | Package marker |
| `src/sycope_recorder/config.py` | `Settings` (pydantic-settings) + `get_settings()`; fail-fast validation |
| `src/sycope_recorder/alert.py` | `ParsedAlert` dataclass + `parse_alert()` (pure) |
| `src/sycope_recorder/bpf.py` | `FILTER_MODES` + `build_bpf_filter()` (pure) |
| `src/sycope_recorder/extraction.py` | `sanitize_id`, `compute_window`, `build_filename` (pure) + `run_extraction()` (subprocess orchestrator) |
| `src/sycope_recorder/logging_config.py` | `setup_logging()` unified logging |
| `src/sycope_recorder/retention.py` | `sweep_once()` + `retention_loop()` |
| `src/sycope_recorder/api.py` | `create_app()`; routes `/healthz`, `/`, `POST /{full_path:path}` |
| `src/sycope_recorder/main.py` | Module-level `app = create_app(get_settings())` for gunicorn |
| `gunicorn.conf.py` | 1 uvicorn worker, unix socket bind, timeout 330 |
| `Dockerfile` | uv-based api image |
| `compose.yaml` | `caddy` + `api` services, volumes, future `recorder` placeholder |
| `caddy/Caddyfile` | TLS internal, auth, allowlist, file_server, reverse_proxy |
| `docs/reference/n2disk.conf`, `docs/reference/n2disk.service` | Carried-forward recorder templates |
| `tests/stubs/npcapextract` | Fake extractor binary for tests |
| `tests/unit/*`, `tests/integration/*` | Test suites |
| `README.md` | Operator/dev quickstart |

---

## Task 0: Project scaffolding

**Files:**
- Create: `pyproject.toml`, `src/sycope_recorder/__init__.py`, `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`, `.gitignore`
- Create: `tests/unit/test_smoke.py`

**Interfaces:**
- Consumes: nothing.
- Produces: an installable `uv` project with a runnable pytest and a `sycope_recorder` importable package.

- [ ] **Step 1: Initialize git and uv project**

```bash
cd /data/projekty/pass/sycope_recorder
git init
uv init --package --name sycope_recorder --python 3.12 --no-workspace .
```

If `uv init` refuses because the directory is non-empty, create `pyproject.toml` manually (Step 2) and skip the rest of the init.

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "sycope_recorder"
version = "0.1.0"
description = "Sycope traffic recorder: alert-triggered PCAP extraction service"
requires-python = ">=3.12"
dependencies = [
    "fastapi",
    "uvicorn[standard]",
    "gunicorn",
    "pydantic",
    "pydantic-settings",
]

[dependency-groups]
dev = [
    "pytest",
    "pytest-asyncio",
    "httpx",
    "ruff",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/sycope_recorder"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
src = ["src", "tests"]
```

- [ ] **Step 3: Create package/test markers and `.gitignore`**

```bash
mkdir -p src/sycope_recorder tests/unit tests/integration
touch src/sycope_recorder/__init__.py tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
```

`.gitignore`:

```gitignore
__pycache__/
*.pyc
.venv/
.pytest_cache/
.ruff_cache/
dist/
caddy/data/
```

- [ ] **Step 4: Write a smoke test**

`tests/unit/test_smoke.py`:

```python
import sycope_recorder


def test_package_imports():
    assert sycope_recorder is not None
```

- [ ] **Step 5: Sync and run**

Run: `uv sync && uv run pytest -q`
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: scaffold uv project, package layout, and test harness"
```

---

## Task 1: Configuration (`config.py`)

**Files:**
- Create: `src/sycope_recorder/config.py`
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class Settings(BaseSettings)` with fields (all overridable via env, prefix `SR_`): `public_host: str`, `download_prefix: str = "downloads"`, `timeline_dir: str = "/storage/pcaps/rolling"`, `output_dir: str = "/storage/pcaps/alerts"`, `default_filter: str = "full"`, `default_before: int = 360`, `default_after: int = 360`, `max_concurrent_extractions: int = 1`, `extract_timeout_seconds: int = 300`, `npcapextract_path: str = "npcapextract"`, `retention_max_age_days: int = 7`, `retention_max_total_bytes: int = 0`, `retention_interval_seconds: int = 3600`, `log_level: str = "INFO"`, `log_format: str = "text"`.
  - `get_settings() -> Settings` (constructs `Settings()`, exits non-zero on validation error).
  - `VALID_FILTER_MODES: frozenset[str]` = `{"full", "hosts", "client", "server", "port"}`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_config.py`:

```python
import pytest
from pydantic import ValidationError

from sycope_recorder.config import Settings, VALID_FILTER_MODES


def test_defaults_apply_when_only_required_present():
    s = Settings(public_host="rec.example.com")
    assert s.download_prefix == "downloads"
    assert s.default_before == 360
    assert s.default_after == 360
    assert s.extract_timeout_seconds == 300
    assert s.max_concurrent_extractions == 1


def test_public_host_is_required():
    with pytest.raises(ValidationError):
        Settings()  # no public_host, no env


def test_env_override(monkeypatch):
    monkeypatch.setenv("SR_PUBLIC_HOST", "host.local")
    monkeypatch.setenv("SR_DEFAULT_BEFORE", "10")
    s = Settings()
    assert s.public_host == "host.local"
    assert s.default_before == 10


def test_max_concurrent_clamped_to_one_minimum():
    assert Settings(public_host="h", max_concurrent_extractions=0).max_concurrent_extractions == 1
    assert Settings(public_host="h", max_concurrent_extractions=-5).max_concurrent_extractions == 1


def test_unknown_default_filter_falls_back_to_full():
    assert Settings(public_host="h", default_filter="bogus").default_filter == "full"
    assert "full" in VALID_FILTER_MODES
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_config.py -q`
Expected: FAIL (`ModuleNotFoundError: sycope_recorder.config`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/config.py`:

```python
from __future__ import annotations

import sys

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_FILTER_MODES: frozenset[str] = frozenset(
    {"full", "hosts", "client", "server", "port"}
)


class Settings(BaseSettings):
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
        return max(1, v)

    @field_validator("default_filter")
    @classmethod
    def _known_filter(cls, v: str) -> str:
        return v if v in VALID_FILTER_MODES else "full"


def get_settings() -> Settings:
    try:
        return Settings()
    except Exception as exc:  # pragma: no cover - exercised at process start
        print(f"ERROR: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_config.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/config.py tests/unit/test_config.py
git commit -m "feat: typed settings via pydantic-settings with fail-fast validation"
```

---

## Task 2: Alert parsing (`alert.py`)

Copies SPEC §5.3 exactly, including the presence-vs-truthiness asymmetry between the flow fields and `id`/`name`.

**Files:**
- Create: `src/sycope_recorder/alert.py`
- Test: `tests/unit/test_alert.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `@dataclass class ParsedAlert` with fields: `client_ip: str | None`, `server_ip: str | None`, `server_port: int | None`, `protocol: str | None`, `timestamp: float` (unix seconds), `alert_id: object` (raw resolved value), `alert_name: str`.
  - `parse_alert(alert: dict, *, now: datetime | None = None) -> ParsedAlert`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_alert.py`:

```python
from datetime import datetime

from sycope_recorder.alert import parse_alert


def test_ip_string_and_dict_forms_and_alias_priority():
    a = parse_alert({"clientIp": "1.1.1.1", "dstIp": {"addressString": "2.2.2.2"}})
    assert a.client_ip == "1.1.1.1"
    assert a.server_ip == "2.2.2.2"


def test_ip_alias_fallback_order():
    a = parse_alert({"source": "9.9.9.9", "destination": "8.8.8.8"})
    assert a.client_ip == "9.9.9.9"
    assert a.server_ip == "8.8.8.8"


def test_port_zero_and_negative_treated_as_absent():
    assert parse_alert({"serverPort": 0}).server_port is None
    assert parse_alert({"serverPort": -3}).server_port is None
    assert parse_alert({"serverPort": "443"}).server_port == 443
    assert parse_alert({"dstPort": 80}).server_port == 80


def test_protocol_int_and_string_mapping():
    assert parse_alert({"protocol": 6}).protocol == "tcp"
    assert parse_alert({"protocol": 17}).protocol == "udp"
    assert parse_alert({"protocol": 1}).protocol == "icmp"
    assert parse_alert({"protocolName": "TCP"}).protocol == "tcp"
    assert parse_alert({"protocol": "http"}).protocol is None
    assert parse_alert({"protocol": 99}).protocol is None


def test_timestamp_ms_vs_seconds_heuristic():
    assert parse_alert({"unixTimestamp": 1_700_000_000}).timestamp == 1_700_000_000
    # value > 1e12 is milliseconds
    assert parse_alert({"time": 1_700_000_000_000}).timestamp == 1_700_000_000


def test_timestamp_string_fallback_day_first_two_digit_year():
    a = parse_alert({"timestamp": "01.07.26 14:03:00"})
    assert datetime.fromtimestamp(a.timestamp).strftime("%Y-%m-%d %H:%M:%S") == "2026-07-01 14:03:00"


def test_timestamp_final_fallback_uses_now():
    fixed = datetime(2030, 1, 2, 3, 4, 5)
    a = parse_alert({}, now=fixed)
    assert a.timestamp == fixed.timestamp()


def test_id_presence_not_truthiness_null_id_kept():
    # 'id' present but null -> kept as-is (becomes "None" downstream), NOT synthesized
    assert parse_alert({"id": None}, now=datetime(2020, 1, 1)).alert_id is None
    # absent -> synthesized alert_<int_ts>
    a = parse_alert({}, now=datetime(2020, 1, 1))
    assert a.alert_id == f"alert_{int(datetime(2020, 1, 1).timestamp())}"
    # alertId used when id absent
    assert parse_alert({"alertId": "X1"}).alert_id == "X1"


def test_name_fallback():
    assert parse_alert({}).alert_name == "Unknown"
    assert parse_alert({"alertName": "Foo"}).alert_name == "Foo"
    assert parse_alert({"name": "Bar", "alertName": "Foo"}).alert_name == "Bar"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_alert.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/alert.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

_PROTO_BY_NUM = {1: "icmp", 6: "tcp", 17: "udp"}
_ALLOWED_PROTO = {"tcp", "udp", "icmp"}


@dataclass
class ParsedAlert:
    client_ip: str | None
    server_ip: str | None
    server_port: int | None
    protocol: str | None
    timestamp: float
    alert_id: Any
    alert_name: str


def _find_field(alert: dict, aliases: list[str], extract: Callable[[Any], Any]) -> Any:
    for name in aliases:
        if name in alert:
            value = extract(alert[name])
            if value:  # truthiness gate (0/""/None/[] -> try next alias)
                return value
    return None


def _ip(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        return value.get("addressString")
    return None


def _port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        try:
            n = int(value)
        except ValueError:
            return None
        return n if n > 0 else None
    return None


def _proto(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _PROTO_BY_NUM.get(value)
    if isinstance(value, str):
        low = value.lower()
        return low if low in _ALLOWED_PROTO else None
    return None


def _numeric_ts(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = float(value)
    elif isinstance(value, str):
        try:
            n = float(value)
        except ValueError:
            return None
    else:
        return None
    return n / 1000.0 if n > 1e12 else n


def _resolve_timestamp(alert: dict, now: datetime) -> float:
    numeric = _find_field(alert, ["unixTimestamp", "timestamp_unix", "time"], _numeric_ts)
    if numeric:
        return numeric
    raw = alert.get("timestamp")
    if isinstance(raw, str):
        try:
            return datetime.strptime(raw, "%d.%m.%y %H:%M:%S").timestamp()
        except ValueError:
            pass
    return now.timestamp()


def parse_alert(alert: dict, *, now: datetime | None = None) -> ParsedAlert:
    now = now or datetime.now()
    client_ip = _find_field(alert, ["clientIp", "srcIp", "src_ip", "sourceIp", "source"], _ip)
    server_ip = _find_field(alert, ["serverIp", "dstIp", "dst_ip", "destIp", "destination"], _ip)
    server_port = _find_field(alert, ["serverPort", "dstPort", "dst_port", "destPort"], _port)
    protocol = _find_field(alert, ["protocolName", "protocol", "proto", "ipProtocol"], _proto)
    timestamp = _resolve_timestamp(alert, now)

    alert_id = alert.get("id", alert.get("alertId", f"alert_{int(timestamp)}"))
    alert_name = alert.get("name", alert.get("alertName", "Unknown"))

    return ParsedAlert(
        client_ip=client_ip,
        server_ip=server_ip,
        server_port=server_port,
        protocol=protocol,
        timestamp=timestamp,
        alert_id=alert_id,
        alert_name=alert_name,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_alert.py -q`
Expected: PASS (9 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/alert.py tests/unit/test_alert.py
git commit -m "feat: alert JSON parsing preserving legacy alias/fallback rules"
```

---

## Task 3: BPF construction (`bpf.py`)

Copies SPEC §5.5 exactly.

**Files:**
- Create: `src/sycope_recorder/bpf.py`
- Test: `tests/unit/test_bpf.py`

**Interfaces:**
- Consumes: `ParsedAlert` (Task 2).
- Produces:
  - `FILTER_MODES: dict[str, tuple[bool, bool, bool]]` mapping mode → (include_client, include_server, include_port).
  - `build_bpf_filter(parsed: ParsedAlert, mode: str) -> str | None`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_bpf.py`:

```python
from sycope_recorder.alert import ParsedAlert
from sycope_recorder.bpf import FILTER_MODES, build_bpf_filter


def mk(**kw) -> ParsedAlert:
    base = dict(
        client_ip=None, server_ip=None, server_port=None,
        protocol=None, timestamp=0.0, alert_id="id", alert_name="n",
    )
    base.update(kw)
    return ParsedAlert(**base)


def test_full_mode_all_terms():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "full") == "tcp and host 1.1.1.1 and host 2.2.2.2 and port 443"


def test_hosts_mode_no_port():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "hosts") == "tcp and host 1.1.1.1 and host 2.2.2.2"


def test_client_and_server_and_port_modes():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="udp")
    assert build_bpf_filter(p, "client") == "udp and host 1.1.1.1"
    assert build_bpf_filter(p, "server") == "udp and host 2.2.2.2"
    assert build_bpf_filter(p, "port") == "udp and host 2.2.2.2 and port 443"


def test_icmp_protocol_dropped_when_port_present():
    p = mk(server_ip="2.2.2.2", server_port=8, protocol="icmp")
    # icmp term dropped because a port is present; port term also excluded (proto is icmp)
    assert build_bpf_filter(p, "full") == "host 2.2.2.2"


def test_icmp_kept_when_no_port():
    p = mk(server_ip="2.2.2.2", protocol="icmp")
    assert build_bpf_filter(p, "full") == "icmp and host 2.2.2.2"


def test_port_term_only_for_tcp_udp_or_unknown():
    # unknown protocol: port term still allowed
    p = mk(server_ip="2.2.2.2", server_port=53)
    assert build_bpf_filter(p, "full") == "host 2.2.2.2 and port 53"


def test_reject_empty_and_bare_protocol_only():
    assert build_bpf_filter(mk(), "full") is None
    assert build_bpf_filter(mk(protocol="tcp"), "full") is None


def test_unknown_mode_treated_as_full():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "bogus") == build_bpf_filter(p, "full")


def test_filter_modes_table():
    assert FILTER_MODES["full"] == (True, True, True)
    assert FILTER_MODES["hosts"] == (True, True, False)
    assert FILTER_MODES["client"] == (True, False, False)
    assert FILTER_MODES["server"] == (False, True, False)
    assert FILTER_MODES["port"] == (False, True, True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_bpf.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/bpf.py`:

```python
from __future__ import annotations

from sycope_recorder.alert import ParsedAlert

# mode -> (include_client_ip, include_server_ip, include_port)
FILTER_MODES: dict[str, tuple[bool, bool, bool]] = {
    "full": (True, True, True),
    "hosts": (True, True, False),
    "client": (True, False, False),
    "server": (False, True, False),
    "port": (False, True, True),
}

_BARE_PROTO = {"tcp", "udp", "icmp"}


def build_bpf_filter(parsed: ParsedAlert, mode: str) -> str | None:
    include_client, include_server, include_port = FILTER_MODES.get(
        mode, FILTER_MODES["full"]
    )

    proto = parsed.protocol
    port = parsed.server_port
    terms: list[str] = []

    # 1. protocol term, unless icmp-with-port
    if proto is not None and not (proto == "icmp" and port is not None):
        terms.append(proto)

    # 2/3. host terms
    if include_client and parsed.client_ip:
        terms.append(f"host {parsed.client_ip}")
    if include_server and parsed.server_ip:
        terms.append(f"host {parsed.server_ip}")

    # 4. port term only for tcp/udp/unknown (never icmp)
    if include_port and port is not None and proto in ("tcp", "udp", None):
        terms.append(f"port {port}")

    # 6. rejection rule
    if not terms or (len(terms) == 1 and terms[0] in _BARE_PROTO):
        return None

    return " and ".join(terms)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_bpf.py -q`
Expected: PASS (9 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/bpf.py tests/unit/test_bpf.py
git commit -m "feat: BPF filter construction preserving legacy term rules"
```

---

## Task 4: Extraction pure helpers (`extraction.py` part 1)

**Files:**
- Create: `src/sycope_recorder/extraction.py`
- Test: `tests/unit/test_extraction_pure.py`

**Interfaces:**
- Consumes: nothing (pure datetime/string helpers).
- Produces:
  - `sanitize_id(raw: object) -> str` — keep `[A-Za-z0-9_-]` from `str(raw)`, truncate to 64, fallback `"alert"` if empty.
  - `TS_FMT = "%Y-%m-%d %H:%M:%S"`.
  - `compute_window(alert_time: datetime, before: int, after: int) -> tuple[str, str]` — `(begin, end)` formatted with `TS_FMT`.
  - `build_filename(alert_time: datetime, raw_id: object) -> str` — `{%Y%m%d_%H%M%S}_{safe_id}.pcap`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_extraction_pure.py`:

```python
from datetime import datetime

from sycope_recorder.extraction import build_filename, compute_window, sanitize_id


def test_sanitize_id_keeps_allowed_chars():
    assert sanitize_id("alert_12345") == "alert_12345"
    assert sanitize_id("a/b c!d-e_f") == "abcd-e_f"


def test_sanitize_id_truncates_to_64():
    assert sanitize_id("x" * 100) == "x" * 64


def test_sanitize_id_empty_fallback():
    assert sanitize_id("!!!") == "alert"
    assert sanitize_id(None) == "alert"  # str(None)="None" -> "None"? see note


def test_sanitize_id_none_becomes_none_string():
    # str(None) == "None", which is all allowed chars -> "None"
    assert sanitize_id(None) == "None"


def test_compute_window():
    t = datetime(2026, 7, 1, 14, 3, 0)
    begin, end = compute_window(t, 360, 360)
    assert begin == "2026-07-01 13:57:00"
    assert end == "2026-07-01 14:09:00"


def test_build_filename():
    t = datetime(2026, 7, 1, 14, 3, 0)
    assert build_filename(t, "alert_12345") == "20260701_140300_alert_12345.pcap"
```

> Note: `test_sanitize_id_empty_fallback`'s `None` assertion contradicts
> `test_sanitize_id_none_becomes_none_string`. Delete the `None` line from
> `test_sanitize_id_empty_fallback` before running — `str(None)` is `"None"`,
> which survives sanitization (legacy behavior, SPEC §5.3 note). Keep the
> `"!!!" -> "alert"` assertion.

- [ ] **Step 2: Fix the test note, then run to verify it fails**

Edit `test_sanitize_id_empty_fallback` to only assert `sanitize_id("!!!") == "alert"`.
Run: `uv run pytest tests/unit/test_extraction_pure.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/extraction.py` (part 1 — pure helpers; `run_extraction` added in Task 5):

```python
from __future__ import annotations

import re
from datetime import datetime, timedelta

TS_FMT = "%Y-%m-%d %H:%M:%S"
_ID_ALLOWED = re.compile(r"[^A-Za-z0-9_-]")


def sanitize_id(raw: object) -> str:
    cleaned = _ID_ALLOWED.sub("", str(raw))[:64]
    return cleaned or "alert"


def compute_window(alert_time: datetime, before: int, after: int) -> tuple[str, str]:
    begin = (alert_time - timedelta(seconds=before)).strftime(TS_FMT)
    end = (alert_time + timedelta(seconds=after)).strftime(TS_FMT)
    return begin, end


def build_filename(alert_time: datetime, raw_id: object) -> str:
    return f"{alert_time:%Y%m%d_%H%M%S}_{sanitize_id(raw_id)}.pcap"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_extraction_pure.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/extraction.py tests/unit/test_extraction_pure.py
git commit -m "feat: pure extraction helpers (id sanitize, window, filename)"
```

---

## Task 5: Extraction orchestrator (`run_extraction`)

Adds the subprocess orchestrator to `extraction.py` and a reusable **stub `npcapextract`** binary for tests.

**Files:**
- Modify: `src/sycope_recorder/extraction.py` (append `run_extraction` + result constants)
- Create: `tests/stubs/npcapextract`
- Test: `tests/unit/test_run_extraction.py`

**Interfaces:**
- Consumes: `ParsedAlert` (Task 2), `build_bpf_filter` (Task 3), pure helpers (Task 4), `Settings` (Task 1).
- Produces:
  - Constants: `NO_BPF = "NO BPF FILTER"`, `ERR_TIMEOUT = "ERROR: npcapextract timeout"`, `ERR_FAILED = "ERROR: npcapextract failed"`.
  - `run_extraction(parsed: ParsedAlert, mode: str, before: int, after: int, settings: Settings) -> str` — synchronous (subprocess.run); returns a download URL on success or one of the constant strings otherwise.

- [ ] **Step 1: Create the stub `npcapextract` binary**

`tests/stubs/npcapextract`:

```bash
#!/usr/bin/env python3
"""Fake npcapextract for tests. Behavior controlled by STUB_MODE env var.

Modes: success (default) | miss | fail | timeout.
Parses -t -b -e -f -o and writes the -o file per mode.
"""
import os
import sys
import time

args = sys.argv[1:]
opts = {}
it = iter(args)
for a in it:
    if a in ("-t", "-b", "-e", "-f", "-o"):
        opts[a] = next(it, None)

# Assert the invocation shape the app must produce.
for required in ("-t", "-b", "-e", "-f", "-o"):
    if opts.get(required) is None:
        sys.stderr.write(f"missing {required}\n")
        sys.exit(2)

mode = os.environ.get("STUB_MODE", "success")
out = opts["-o"]

if mode == "timeout":
    time.sleep(3600)
elif mode == "fail":
    sys.stderr.write("simulated failure\n")
    sys.exit(1)
elif mode == "miss":
    open(out, "wb").close()  # zero-byte file, rc 0
    sys.exit(0)
else:  # success
    with open(out, "wb") as fh:
        fh.write(b"PCAPDATA")
    sys.exit(0)
```

```bash
chmod +x tests/stubs/npcapextract
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_run_extraction.py`:

```python
import os
from datetime import datetime
from pathlib import Path

import pytest

from sycope_recorder.alert import ParsedAlert
from sycope_recorder.config import Settings
from sycope_recorder.extraction import (
    ERR_FAILED,
    ERR_TIMEOUT,
    NO_BPF,
    run_extraction,
)

STUB = str(Path(__file__).resolve().parents[1] / "stubs" / "npcapextract")


def make_settings(tmp_path: Path, **kw) -> Settings:
    base = dict(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
        npcapextract_path=STUB,
        extract_timeout_seconds=2,
    )
    base.update(kw)
    return Settings(**base)


def full_alert(ts: float) -> ParsedAlert:
    return ParsedAlert(
        client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443,
        protocol="tcp", timestamp=ts, alert_id="alert_12345", alert_name="n",
    )


def test_success_returns_https_url(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    s = make_settings(tmp_path)
    ts = datetime(2026, 7, 1, 14, 3, 0).timestamp()
    result = run_extraction(full_alert(ts), "full", 360, 360, s)
    assert result == (
        "https://rec.example.com/downloads/20260701_140300_alert_12345.pcap"
    )
    assert (tmp_path / "alerts" / "20260701_140300_alert_12345.pcap").exists()


def test_no_bpf_returns_early_without_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "fail")  # would fail IF it ran
    s = make_settings(tmp_path)
    empty = ParsedAlert(None, None, None, None, 0.0, "id", "n")
    assert run_extraction(empty, "full", 1, 1, s) == NO_BPF


def test_miss_zero_byte_reports_failed_and_deletes_file(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "miss")
    s = make_settings(tmp_path)
    ts = datetime(2026, 7, 1, 14, 3, 0).timestamp()
    assert run_extraction(full_alert(ts), "full", 1, 1, s) == ERR_FAILED
    assert not (tmp_path / "alerts" / "20260701_140300_alert_12345.pcap").exists()


def test_nonzero_exit_reports_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "fail")
    s = make_settings(tmp_path)
    assert run_extraction(full_alert(0.0), "full", 1, 1, s) == ERR_FAILED


def test_timeout_reports_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "timeout")
    s = make_settings(tmp_path, extract_timeout_seconds=1)
    assert run_extraction(full_alert(0.0), "full", 1, 1, s) == ERR_TIMEOUT
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_run_extraction.py -q`
Expected: FAIL (`ImportError: cannot import name 'run_extraction'`).

- [ ] **Step 4: Append the implementation to `extraction.py`**

Add to the imports at the top of `src/sycope_recorder/extraction.py`:

```python
import logging
import os
import subprocess

from sycope_recorder.alert import ParsedAlert
from sycope_recorder.bpf import build_bpf_filter
from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")

NO_BPF = "NO BPF FILTER"
ERR_TIMEOUT = "ERROR: npcapextract timeout"
ERR_FAILED = "ERROR: npcapextract failed"
```

Append at the end of the file:

```python
def run_extraction(
    parsed: ParsedAlert,
    mode: str,
    before: int,
    after: int,
    settings: Settings,
) -> str:
    alert_time = datetime.fromtimestamp(parsed.timestamp)

    bpf = build_bpf_filter(parsed, mode)
    if not bpf:
        log.info("NO BPF FILTER for alert id=%s", parsed.alert_id)
        return NO_BPF

    os.makedirs(settings.output_dir, exist_ok=True)
    filename = build_filename(alert_time, parsed.alert_id)
    output_path = os.path.join(settings.output_dir, filename)
    begin, end = compute_window(alert_time, before, after)

    cmd = [
        settings.npcapextract_path,
        "-t", settings.timeline_dir,
        "-b", begin,
        "-e", end,
        "-f", bpf,
        "-o", output_path,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.extract_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        log.error("npcapextract timeout after %ss (id=%s)",
                  settings.extract_timeout_seconds, parsed.alert_id)
        return ERR_TIMEOUT

    ok = (
        proc.returncode == 0
        and os.path.exists(output_path)
        and os.path.getsize(output_path) > 0
    )
    if ok:
        size = os.path.getsize(output_path)
        url = f"https://{settings.public_host}/{settings.download_prefix}/{filename}"
        log.info("SUCCESS: %s (%d bytes) URL: %s", output_path, size, url)
        return url

    # Zero-byte "MISS": rc 0 but nothing matched. Distinct log, merged response.
    if proc.returncode == 0 and os.path.exists(output_path):
        log.info("MISS: no packets matched (id=%s); removing %s",
                 parsed.alert_id, output_path)
        try:
            os.remove(output_path)
        except OSError:
            pass

    log.error("npcapextract failed rc=%s stdout=%r stderr=%r",
              proc.returncode, proc.stdout, proc.stderr)
    return ERR_FAILED
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_run_extraction.py -q`
Expected: PASS (5 passed). (The timeout test takes ~1s.)

- [ ] **Step 6: Commit**

```bash
git add src/sycope_recorder/extraction.py tests/stubs/npcapextract tests/unit/test_run_extraction.py
git commit -m "feat: run_extraction subprocess orchestrator + test stub binary"
```

---

## Task 6: Unified logging (`logging_config.py`)

**Files:**
- Create: `src/sycope_recorder/logging_config.py`
- Test: `tests/unit/test_logging.py`

**Interfaces:**
- Consumes: `Settings` (for `log_level`, `log_format`).
- Produces: `setup_logging(settings: Settings) -> None` — configures the root logger once to stdout with the legacy text format `%(asctime)s [%(levelname)s] %(message)s` (or a JSON line format when `log_format == "json"`), and quiets uvicorn access noise.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_logging.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_logging.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/logging_config.py`:

```python
from __future__ import annotations

import logging
import sys

from sycope_recorder.config import Settings

_TEXT_FMT = "%(asctime)s [%(levelname)s] %(message)s"
_JSON_FMT = (
    '{"time":"%(asctime)s","level":"%(levelname)s",'
    '"logger":"%(name)s","message":"%(message)s"}'
)


def setup_logging(settings: Settings) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    fmt = _JSON_FMT if settings.log_format == "json" else _TEXT_FMT
    handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())

    # Route uvicorn/gunicorn logs through the same handler; drop access spam.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error", "gunicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_logging.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/logging_config.py tests/unit/test_logging.py
git commit -m "feat: unified logging configuration"
```

---

## Task 7: Retention (`retention.py`)

**Files:**
- Create: `src/sycope_recorder/retention.py`
- Test: `tests/unit/test_retention.py`

**Interfaces:**
- Consumes: `Settings`.
- Produces:
  - `sweep_once(output_dir: str, max_age_seconds: int, max_total_bytes: int, now: float) -> dict` — returns `{"deleted": int, "bytes": int}`; deletes by age then oldest-first size cap; `0` disables a rule; never raises on per-file errors.
  - `async retention_loop(settings: Settings, stop: asyncio.Event) -> None` — sweeps every `retention_interval_seconds` until `stop` is set.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_retention.py`:

```python
import os
import time
from pathlib import Path

from sycope_recorder.retention import sweep_once


def make_pcap(d: Path, name: str, size: int, age_seconds: float, now: float) -> Path:
    p = d / name
    p.write_bytes(b"x" * size)
    mtime = now - age_seconds
    os.utime(p, (mtime, mtime))
    return p


def test_age_based_deletion(tmp_path):
    now = time.time()
    old = make_pcap(tmp_path, "old.pcap", 10, age_seconds=100_000, now=now)
    new = make_pcap(tmp_path, "new.pcap", 10, age_seconds=1, now=now)
    stats = sweep_once(str(tmp_path), max_age_seconds=3600, max_total_bytes=0, now=now)
    assert not old.exists()
    assert new.exists()
    assert stats["deleted"] == 1


def test_size_cap_deletes_oldest_first(tmp_path):
    now = time.time()
    a = make_pcap(tmp_path, "a.pcap", 100, age_seconds=300, now=now)
    b = make_pcap(tmp_path, "b.pcap", 100, age_seconds=200, now=now)
    c = make_pcap(tmp_path, "c.pcap", 100, age_seconds=100, now=now)
    # cap = 250 bytes -> must delete oldest (a) then next-oldest (b) to reach <=250
    sweep_once(str(tmp_path), max_age_seconds=0, max_total_bytes=250, now=now)
    assert not a.exists()
    assert not b.exists()
    assert c.exists()


def test_disabled_rules_delete_nothing(tmp_path):
    now = time.time()
    p = make_pcap(tmp_path, "keep.pcap", 10, age_seconds=999_999, now=now)
    stats = sweep_once(str(tmp_path), max_age_seconds=0, max_total_bytes=0, now=now)
    assert p.exists()
    assert stats["deleted"] == 0


def test_only_pcap_files_considered(tmp_path):
    now = time.time()
    other = tmp_path / "notes.txt"
    other.write_bytes(b"x" * 10)
    os.utime(other, (now - 999_999, now - 999_999))
    sweep_once(str(tmp_path), max_age_seconds=1, max_total_bytes=0, now=now)
    assert other.exists()


def test_missing_dir_is_safe(tmp_path):
    stats = sweep_once(str(tmp_path / "nope"), 1, 1, time.time())
    assert stats == {"deleted": 0, "bytes": 0}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_retention.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/retention.py`:

```python
from __future__ import annotations

import asyncio
import logging
import os
import time

from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")


def _entries(output_dir: str) -> list[tuple[str, float, int]]:
    result: list[tuple[str, float, int]] = []
    try:
        names = os.listdir(output_dir)
    except OSError:
        return result
    for name in names:
        if not name.endswith(".pcap"):
            continue
        path = os.path.join(output_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if os.path.isfile(path):
            result.append((path, st.st_mtime, st.st_size))
    return result


def _delete(path: str) -> int:
    try:
        size = os.path.getsize(path)
        os.remove(path)
        return size
    except OSError as exc:
        log.warning("retention: could not delete %s: %s", path, exc)
        return 0


def sweep_once(
    output_dir: str, max_age_seconds: int, max_total_bytes: int, now: float
) -> dict:
    deleted = 0
    reclaimed = 0

    entries = _entries(output_dir)

    if max_age_seconds > 0:
        survivors = []
        for path, mtime, size in entries:
            if now - mtime > max_age_seconds:
                freed = _delete(path)
                if freed or not os.path.exists(path):
                    deleted += 1
                    reclaimed += freed
            else:
                survivors.append((path, mtime, size))
        entries = survivors

    if max_total_bytes > 0:
        total = sum(size for _, _, size in entries)
        for path, _mtime, size in sorted(entries, key=lambda e: e[1]):  # oldest first
            if total <= max_total_bytes:
                break
            freed = _delete(path)
            if freed or not os.path.exists(path):
                deleted += 1
                reclaimed += freed
                total -= size

    if deleted:
        log.info("retention: deleted %d file(s), reclaimed %d bytes", deleted, reclaimed)
    return {"deleted": deleted, "bytes": reclaimed}


async def retention_loop(settings: Settings, stop: asyncio.Event) -> None:
    max_age = settings.retention_max_age_days * 86400
    while not stop.is_set():
        try:
            sweep_once(
                settings.output_dir,
                max_age,
                settings.retention_max_total_bytes,
                time.time(),
            )
        except Exception as exc:  # never let the sweep kill the loop
            log.warning("retention sweep error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.retention_interval_seconds)
        except asyncio.TimeoutError:
            continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_retention.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/retention.py tests/unit/test_retention.py
git commit -m "feat: age + size-cap retention sweep and background loop"
```

---

## Task 8: API app — health and help (`api.py` part 1)

**Files:**
- Create: `src/sycope_recorder/api.py`
- Test: `tests/integration/test_api_basic.py`

**Interfaces:**
- Consumes: `Settings`, `setup_logging`, `retention_loop` (lifespan wiring added in Task 10; here the app is created without the retention task for isolated testing via a `start_retention` flag).
- Produces:
  - `create_app(settings: Settings, *, start_retention: bool = True) -> FastAPI`.
  - `GET /healthz` → 200 JSON `{"status": "ok", "timeline_dir_present": bool, "output_dir_present": bool}` (no auth).
  - `GET /` → 200 JSON help body with keys `status` (`"ok"`), `usage` (with `endpoint`, `filter_modes`, `defaults`), `examples` (3 strings).

- [ ] **Step 1: Write the failing test**

`tests/integration/test_api_basic.py`:

```python
from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings


def client(tmp_path) -> TestClient:
    s = Settings(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
    )
    return TestClient(create_app(s, start_retention=False))


def test_healthz_ok_no_auth(tmp_path):
    r = client(tmp_path).get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_help_endpoint_shape(tmp_path):
    r = client(tmp_path).get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert set(body["usage"]) == {"endpoint", "filter_modes", "defaults"}
    assert set(body["usage"]["filter_modes"]) == {"full", "hosts", "client", "server", "port"}
    assert body["usage"]["defaults"]["filter"] == "full"
    assert len(body["examples"]) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_api_basic.py -q`
Expected: FAIL (`ModuleNotFoundError: sycope_recorder.api`).

- [ ] **Step 3: Write the implementation**

`src/sycope_recorder/api.py`:

```python
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from sycope_recorder.bpf import FILTER_MODES
from sycope_recorder.config import Settings


def _help_body(settings: Settings) -> dict:
    return {
        "status": "ok",
        "usage": {
            "endpoint": "POST /extract?filter=MODE&before=SEC&after=SEC",
            "filter_modes": {
                "full": "client IP, server IP, and port",
                "hosts": "client IP and server IP",
                "client": "client IP only",
                "server": "server IP only",
                "port": "server IP and port",
            },
            "defaults": {
                "filter": settings.default_filter,
                "before": settings.default_before,
                "after": settings.default_after,
            },
        },
        "examples": [
            "POST /extract?filter=full&before=30&after=60",
            "POST /extract?filter=hosts",
            "POST /extract?filter=port&before=120&after=120",
        ],
    }


def create_app(settings: Settings, *, start_retention: bool = True) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "timeline_dir_present": os.path.isdir(settings.timeline_dir),
                "output_dir_present": os.path.isdir(settings.output_dir),
            }
        )

    @app.get("/")
    def help_endpoint() -> JSONResponse:
        return JSONResponse(_help_body(settings))

    assert FILTER_MODES  # ensures import used; extract route added in Task 9
    return app
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_api_basic.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/sycope_recorder/api.py tests/integration/test_api_basic.py
git commit -m "feat: FastAPI app with /healthz and help endpoints"
```

---

## Task 9: API app — `/extract` (`api.py` part 2)

Adds the webhook endpoint with body validation, query-param resolution, the single-worker concurrency gate, and the all-200 response contract.

**Files:**
- Modify: `src/sycope_recorder/api.py` (add imports, param helpers, and the POST route)
- Test: `tests/integration/test_extract.py`

**Interfaces:**
- Consumes: `parse_alert`, `run_extraction`, `run_extraction` result constants, `VALID_FILTER_MODES`.
- Produces: `POST /{full_path:path}` handler (catches `/extract` and any other POST path for legacy leniency), returning `PlainTextResponse` with an `X-Result` header.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_extract.py`:

```python
import json
from pathlib import Path

from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings

STUB = str(Path(__file__).resolve().parents[1] / "stubs" / "npcapextract")


def client(tmp_path, **kw) -> TestClient:
    s = Settings(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
        npcapextract_path=STUB,
        extract_timeout_seconds=2,
        **kw,
    )
    return TestClient(create_app(s, start_retention=False))


ALERT = {
    "id": "alert_12345",
    "clientIp": "1.1.1.1",
    "serverIp": "2.2.2.2",
    "serverPort": 443,
    "protocol": "tcp",
    "unixTimestamp": 1_782_050_580,  # 2026-07-01 ~ local
}


def test_success_returns_200_url_and_x_result(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    r = client(tmp_path).post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 200
    assert r.text.startswith("https://rec.example.com/downloads/")
    assert r.text.endswith("_alert_12345.pcap")
    assert r.headers["X-Result"] == r.text


def test_any_post_path_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    r = client(tmp_path).post("/anything", content=json.dumps(ALERT))
    assert r.status_code == 200


def test_no_bpf_when_no_flow_fields(tmp_path):
    r = client(tmp_path).post("/extract", content=json.dumps({"id": "x"}))
    assert r.status_code == 200
    assert r.text == "NO BPF FILTER"


def test_miss_and_failure_report_error(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "miss")
    r = client(tmp_path).post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 200
    assert r.text == "ERROR: npcapextract failed"


def test_empty_body_400(tmp_path):
    r = client(tmp_path).post("/extract", content=b"")
    assert r.status_code == 400
    assert r.text == "Empty request body"


def test_invalid_json_400(tmp_path):
    r = client(tmp_path).post("/extract", content=b"{not json")
    assert r.status_code == 400
    assert r.text == "Invalid JSON"


def test_payload_too_large_413(tmp_path):
    big = b"x" * (2 * 1024 * 1024 + 1)
    r = client(tmp_path).post("/extract", content=big)
    assert r.status_code == 413
    assert r.text == "Payload too large"


def test_query_param_clamping(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    # invalid before/after fall back to defaults; huge values clamp to 86400
    r = client(tmp_path).post(
        "/extract?filter=bogus&before=notanint&after=999999", content=json.dumps(ALERT)
    )
    assert r.status_code == 200  # bogus filter -> default full; extraction still runs
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_extract.py -q`
Expected: FAIL (POST returns 404/405 — route not defined yet).

- [ ] **Step 3: Add imports and the concurrency counter to `create_app`**

At the top of `src/sycope_recorder/api.py`, extend imports:

```python
import asyncio
import json
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from sycope_recorder.alert import parse_alert
from sycope_recorder.config import Settings, VALID_FILTER_MODES
from sycope_recorder.extraction import run_extraction

log = logging.getLogger("sycope_recorder")

MAX_BODY_BYTES = 2 * 1024 * 1024
CLAMP_MIN, CLAMP_MAX = 0, 86400
```

Inside `create_app`, after `app.state.settings = settings`, add:

```python
    app.state.active_extractions = 0  # single-worker gate; no lock needed
```

- [ ] **Step 4: Add param helpers and the POST route (append inside `create_app`, before `return app`)**

```python
    def _resolve_params(request: Request) -> tuple[str, int, int]:
        q = request.query_params
        mode = q.get("filter") or settings.default_filter
        if mode not in VALID_FILTER_MODES:
            log.warning("unknown filter mode %r; using %s", mode, settings.default_filter)
            mode = settings.default_filter if settings.default_filter in VALID_FILTER_MODES else "full"

        def _int(name: str, default: int) -> int:
            raw = q.get(name)
            if raw is None:
                return default
            try:
                val = int(raw)
            except ValueError:
                log.warning("invalid %s=%r; using default %d", name, raw, default)
                return default
            return max(CLAMP_MIN, min(CLAMP_MAX, val))

        return mode, _int("before", settings.default_before), _int("after", settings.default_after)

    @app.post("/{full_path:path}")
    async def extract(request: Request) -> PlainTextResponse:
        cl = request.headers.get("content-length")
        if cl is None:
            return PlainTextResponse("Missing Content-Length", status_code=411)
        try:
            length = int(cl)
        except ValueError:
            return PlainTextResponse("Invalid Content-Length", status_code=400)
        if length > MAX_BODY_BYTES:
            return PlainTextResponse("Payload too large", status_code=413)

        body = await request.body()
        if not body:
            return PlainTextResponse("Empty request body", status_code=400)
        try:
            alert = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("invalid JSON body (%d bytes): %s", len(body), exc)
            return PlainTextResponse("Invalid JSON", status_code=400)

        if app.state.active_extractions >= settings.max_concurrent_extractions:
            return PlainTextResponse(
                "Too many concurrent extractions",
                status_code=429,
                headers={"Retry-After": "5"},
            )

        try:
            mode, before, after = _resolve_params(request)
            parsed = parse_alert(alert)
            log.info("=" * 60)
            log.info("Alert id=%s name=%s keys=%s", parsed.alert_id, parsed.alert_name, list(alert))
            log.info("params: filter=%s before=%d after=%d", mode, before, after)
            log.info(
                "flow: %s -> %s:%s (%s)",
                parsed.client_ip, parsed.server_ip, parsed.server_port, parsed.protocol,
            )
            if not parsed.client_ip or not parsed.server_ip:
                log.warning("missing IP(s); BPF may be empty")

            app.state.active_extractions += 1
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, run_extraction, parsed, mode, before, after, settings
                )
            finally:
                app.state.active_extractions -= 1

            return PlainTextResponse(result, headers={"X-Result": result})
        except Exception:  # generic 500, no detail leak
            log.exception("unhandled error during extraction")
            return PlainTextResponse("Internal error", status_code=500)
```

Also remove the now-unused `assert FILTER_MODES` line from Task 8 (the import is still used by the help body).

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_extract.py -q`
Expected: PASS (8 passed).

- [ ] **Step 6: Add the concurrency 429 test**

Append to `tests/integration/test_extract.py`:

```python
def test_concurrency_gate_returns_429(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    c = client(tmp_path)
    app = c.app
    app.state.active_extractions = app.state.settings.max_concurrent_extractions
    r = c.post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "5"
    assert r.text == "Too many concurrent extractions"
```

Run: `uv run pytest tests/integration/test_extract.py -q`
Expected: PASS (9 passed).

- [ ] **Step 7: Commit**

```bash
git add src/sycope_recorder/api.py tests/integration/test_extract.py
git commit -m "feat: /extract endpoint with validation, concurrency gate, all-200 contract"
```

---

## Task 10: App wiring & gunicorn config (`main.py`, `gunicorn.conf.py`)

Wires the retention background task into the app lifespan and provides the gunicorn entrypoint.

**Files:**
- Modify: `src/sycope_recorder/api.py` (add lifespan starting `retention_loop` when `start_retention=True`)
- Create: `src/sycope_recorder/main.py`
- Create: `gunicorn.conf.py`
- Test: `tests/integration/test_lifespan.py`

**Interfaces:**
- Consumes: `retention_loop`, `setup_logging`, `get_settings`.
- Produces: module-level `app` in `main.py` for `gunicorn sycope_recorder.main:app`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_lifespan.py`:

```python
from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings


def test_retention_task_starts_and_stops(tmp_path):
    s = Settings(
        public_host="h",
        output_dir=str(tmp_path / "alerts"),
        retention_interval_seconds=3600,
    )
    app = create_app(s, start_retention=True)
    with TestClient(app) as c:  # triggers startup + shutdown
        assert c.get("/healthz").status_code == 200
        assert app.state.retention_task is not None
    # after context exit, task is cancelled/finished
    assert app.state.retention_task.done()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_lifespan.py -q`
Expected: FAIL (`AttributeError: retention_task`).

- [ ] **Step 3: Add lifespan to `create_app`**

In `src/sycope_recorder/api.py`, add imports:

```python
from contextlib import asynccontextmanager

from sycope_recorder.retention import retention_loop
```

Replace the `app = FastAPI(...)` construction in `create_app` with a lifespan-aware version:

```python
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.retention_stop = asyncio.Event()
        app.state.retention_task = None
        if start_retention:
            app.state.retention_task = asyncio.create_task(
                retention_loop(settings, app.state.retention_stop)
            )
        try:
            yield
        finally:
            if app.state.retention_task is not None:
                app.state.retention_stop.set()
                app.state.retention_task.cancel()
                try:
                    await app.state.retention_task
                except (asyncio.CancelledError, Exception):
                    pass

    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
```

(Keep the rest of `create_app` — state, routes — unchanged. Ensure `app.state.retention_task` also exists when `start_retention=False`: it is set inside lifespan, so tests that never enter the context won't touch it; the `test_lifespan` test uses the `with TestClient(app)` context.)

- [ ] **Step 4: Write `main.py` and `gunicorn.conf.py`**

`src/sycope_recorder/main.py`:

```python
from __future__ import annotations

from sycope_recorder.api import create_app
from sycope_recorder.config import get_settings
from sycope_recorder.logging_config import setup_logging

settings = get_settings()
setup_logging(settings)
app = create_app(settings)
```

`gunicorn.conf.py`:

```python
import os

bind = os.environ.get("SR_BIND", "unix:/run/api/api.sock")
workers = 1
worker_class = "uvicorn.workers.UvicornWorker"
# Must exceed SR_EXTRACT_TIMEOUT_SECONDS (default 300) so long extractions survive.
timeout = int(os.environ.get("SR_GUNICORN_TIMEOUT", "330"))
graceful_timeout = int(os.environ.get("SR_GUNICORN_GRACEFUL_TIMEOUT", "30"))
loglevel = os.environ.get("SR_LOG_LEVEL", "info").lower()
accesslog = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_lifespan.py -q`
Expected: PASS (1 passed).
Run: `uv run pytest -q`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/sycope_recorder/api.py src/sycope_recorder/main.py gunicorn.conf.py tests/integration/test_lifespan.py
git commit -m "feat: lifespan-managed retention task and gunicorn entrypoint"
```

---

## Task 11: Caddy configuration (`caddy/Caddyfile`)

Config-only (no automated test; validated with `caddy validate` and reviewed against SPEC §6).

**Files:**
- Create: `caddy/Caddyfile`

**Interfaces:**
- Consumes: env vars `SR_PUBLIC_HOST`, `SR_DOWNLOAD_PREFIX` (default `downloads`), `BASIC_AUTH_USER`, `BASIC_AUTH_HASH` (bcrypt), `ALLOWED_IPS` (space-separated CIDRs; empty = allow all).

- [ ] **Step 1: Write the Caddyfile**

`caddy/Caddyfile`:

```caddyfile
{
	admin off
}

{$SR_PUBLIC_HOST} {
	tls internal

	# Health probe: no auth.
	handle /healthz {
		reverse_proxy unix//run/api/api.sock
	}

	# Static PCAP downloads served directly by Caddy (auth + optional IP allowlist).
	handle_path /{$SR_DOWNLOAD_PREFIX:downloads}/* {
		@denied not remote_ip {$ALLOWED_IPS:0.0.0.0/0 ::/0}
		respond @denied "Forbidden" 403

		basic_auth {
			{$BASIC_AUTH_USER} {$BASIC_AUTH_HASH}
		}
		root * /srv/alerts
		file_server {
			browse off
		}
	}

	# Everything else (POST /extract, GET /) -> API over unix socket, behind auth.
	handle {
		basic_auth {
			{$BASIC_AUTH_USER} {$BASIC_AUTH_HASH}
		}
		reverse_proxy unix//run/api/api.sock
	}
}
```

> Notes for the operator (put in README, Task 13): generate the bcrypt hash with
> `caddy hash-password`; set `ALLOWED_IPS` to a space-separated list to restrict
> downloads (and optionally add a matching `@denied` guard to the `handle` block
> for `/extract` if Sycope's source IP is fixed). `handle_path` strips the
> `/downloads` prefix so files resolve directly under `/srv/alerts`.

- [ ] **Step 2: Validate (if caddy is available locally)**

Run: `caddy validate --config caddy/Caddyfile --adapter caddyfile` (or defer to the compose build in Task 12).
Expected: "Valid configuration" (or skip if `caddy` isn't installed locally — it is validated in the container).

- [ ] **Step 3: Commit**

```bash
git add caddy/Caddyfile
git commit -m "feat: Caddy edge config (tls internal, auth, allowlist, file_server, proxy)"
```

---

## Task 12: Docker packaging (`Dockerfile`, `compose.yaml`)

**Files:**
- Create: `Dockerfile`
- Create: `compose.yaml`
- Create: `.dockerignore`

**Interfaces:**
- Produces: an `api` image running gunicorn on the unix socket, and a compose stack with `caddy` + `api` sharing the socket and alerts volumes.

- [ ] **Step 1: Write `.dockerignore`**

`.dockerignore`:

```dockerignore
.git
.venv
__pycache__
.pytest_cache
.ruff_cache
tests
docs
dist
caddy/data
```

- [ ] **Step 2: Write the `Dockerfile`**

`Dockerfile`:

```dockerfile
FROM python:3.12-slim

# uv for dependency management.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install locked dependencies first (better layer caching).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# App source.
COPY src ./src
COPY gunicorn.conf.py ./
RUN uv sync --frozen --no-dev

# npcapextract placement is deferred (SPEC v2 design §8.3); it is expected on
# PATH at runtime (installed here or provided via the recorder integration).

# Socket dir shared with Caddy.
RUN mkdir -p /run/api

ENV PATH="/app/.venv/bin:${PATH}"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "sycope_recorder.main:app"]
```

- [ ] **Step 3: Write `compose.yaml`**

`compose.yaml`:

```yaml
services:
  api:
    build: .
    restart: unless-stopped
    environment:
      SR_PUBLIC_HOST: ${SR_PUBLIC_HOST:?set SR_PUBLIC_HOST}
      SR_DOWNLOAD_PREFIX: ${SR_DOWNLOAD_PREFIX:-downloads}
      SR_TIMELINE_DIR: /storage/pcaps/rolling
      SR_OUTPUT_DIR: /storage/pcaps/alerts
      SR_MAX_CONCURRENT_EXTRACTIONS: ${SR_MAX_CONCURRENT_EXTRACTIONS:-1}
      SR_EXTRACT_TIMEOUT_SECONDS: ${SR_EXTRACT_TIMEOUT_SECONDS:-300}
      SR_RETENTION_MAX_AGE_DAYS: ${SR_RETENTION_MAX_AGE_DAYS:-7}
      SR_RETENTION_MAX_TOTAL_BYTES: ${SR_RETENTION_MAX_TOTAL_BYTES:-0}
      SR_LOG_FORMAT: ${SR_LOG_FORMAT:-text}
    volumes:
      - rolling:/storage/pcaps/rolling:ro
      - alerts:/storage/pcaps/alerts
      - run:/run/api
    # Healthcheck runs inside the container against the unix socket.
    healthcheck:
      test: ["CMD", "python", "-c",
             "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect('/run/api/api.sock'); s.sendall(b'GET /healthz HTTP/1.0\\r\\n\\r\\n'); sys.exit(0 if b'200' in s.recv(1024) else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  caddy:
    image: caddy:2
    restart: unless-stopped
    depends_on:
      - api
    ports:
      - "443:443"
      - "80:80"
    environment:
      SR_PUBLIC_HOST: ${SR_PUBLIC_HOST:?set SR_PUBLIC_HOST}
      SR_DOWNLOAD_PREFIX: ${SR_DOWNLOAD_PREFIX:-downloads}
      BASIC_AUTH_USER: ${BASIC_AUTH_USER:?set BASIC_AUTH_USER}
      BASIC_AUTH_HASH: ${BASIC_AUTH_HASH:?set BASIC_AUTH_HASH}
      ALLOWED_IPS: ${ALLOWED_IPS:-0.0.0.0/0 ::/0}
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - alerts:/srv/alerts:ro
      - run:/run/api:ro
      - caddy_data:/data
      - caddy_config:/config

  # Future recorder (n2disk). Attaches to the rolling volume; needs capture
  # privileges (host network / NET_RAW / --privileged). Templates in
  # docs/reference/. Uncomment and complete when integrating the recorder.
  # recorder:
  #   image: <n2disk-image>
  #   restart: unless-stopped
  #   network_mode: host
  #   cap_add: ["NET_RAW", "NET_ADMIN"]
  #   volumes:
  #     - rolling:/storage/pcaps/rolling

volumes:
  rolling:
  alerts:
  run:
  caddy_data:
  caddy_config:
```

- [ ] **Step 4: Build and validate the stack config**

Run: `uv lock` (ensure `uv.lock` exists and is current)
Run: `docker compose build api`
Expected: image builds successfully.
Run: `SR_PUBLIC_HOST=rec.local BASIC_AUTH_USER=u BASIC_AUTH_HASH='$2a$14$abc' docker compose config`
Expected: rendered config with no errors (Caddyfile syntax is validated by the caddy image at run time).

- [ ] **Step 5: Commit**

```bash
git add Dockerfile compose.yaml .dockerignore uv.lock
git commit -m "feat: Docker image and compose stack (api + caddy, future recorder)"
```

---

## Task 13: Reference material and README

**Files:**
- Create: `docs/reference/n2disk.conf`, `docs/reference/n2disk.service`
- Create: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Carry forward the n2disk templates**

`docs/reference/n2disk.conf` (verbatim from `old/config/n2disk.conf`):

```
-i=ens18
-o=/storage/pcaps/rolling
--index
--timeline-dir=/storage/pcaps/rolling
--max-file-duration=300
-b=2048
-p=500
--disk-limit 80%
```

`docs/reference/n2disk.service` (verbatim from `old/config/n2disk.service`):

```ini
[Unit]
Description=n2disk packet recorder
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/n2disk /etc/n2disk/n2disk.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write `README.md`**

`README.md`:

````markdown
# Sycope Traffic Recorder v2

Alert-triggered PCAP extraction service. Sycope calls `POST /extract`; the
service builds a BPF filter from the alert, runs `npcapextract` against the
n2disk rolling capture, and returns an HTTPS download URL. Files are served by
Caddy; the API runs FastAPI under gunicorn.

See `docs/superpowers/specs/2026-07-01-sycope-recorder-v2-design.md` for the
design and `SPEC.md` for the preserved legacy behavioral contract.

## Quickstart (Docker)

```bash
# 1. Generate a bcrypt hash for the shared Basic-auth credential:
docker run --rm caddy:2 caddy hash-password --plaintext 'yourpassword'

# 2. Set required environment and launch:
export SR_PUBLIC_HOST=recorder.example.com
export BASIC_AUTH_USER=sycope
export BASIC_AUTH_HASH='<paste the hash>'
# optional: restrict downloads (and optionally /extract) by source IP
export ALLOWED_IPS="10.0.0.0/8 192.168.0.0/16"
docker compose up -d --build
```

The API listens only on a unix socket; Caddy publishes 443 (and 80→redirect)
with a self-signed cert from its internal CA. Point Sycope's webhook at
`https://$SR_PUBLIC_HOST/extract` with the Basic-auth credential; clients must
trust Caddy's internal CA or skip verification.

## Configuration

All app settings use the `SR_` env prefix — see `src/sycope_recorder/config.py`
for the full list and defaults (host, dirs, filter/before/after defaults,
`max_concurrent_extractions`, `extract_timeout_seconds`, retention knobs,
logging). Auth and the download IP allowlist are configured in Caddy, not the
app.

## The recorder (n2disk)

n2disk is not yet containerized. Templates for its config and systemd unit are
in `docs/reference/`. When integrating it as a compose service, attach it to the
`rolling` volume with capture privileges (see the commented `recorder` block in
`compose.yaml`), and decide where the `npcapextract` binary lives (bundled in
the API image or invoked from the recorder container).

## Development

```bash
uv sync
uv run pytest -q     # unit + integration; uses a stub npcapextract, no n2disk
uv run ruff check .
```
````

- [ ] **Step 3: Commit**

```bash
git add docs/reference/n2disk.conf docs/reference/n2disk.service README.md
git commit -m "docs: n2disk reference templates and README"
```

---

## Task 14: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Run the whole suite**

Run: `uv run pytest -q`
Expected: all tests PASS (no failures, no errors).

- [ ] **Step 2: Lint**

Run: `uv run ruff check .`
Expected: no errors (fix any reported issues, re-run, commit fixes if needed).

- [ ] **Step 3: Build the image**

Run: `docker compose build`
Expected: both images resolve/build successfully.

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "chore: final lint/verification fixes" || echo "nothing to commit"
```

---

## Self-Review Notes (author checklist — completed)

- **Spec coverage:** config→T1; alert parsing→T2; BPF→T3; window/filename/id→T4; npcapextract invocation + MISS/timeout/failure classification + https URL→T5; unified logging→T6; age+size retention→T7; /healthz + help→T8; /extract validation + all-200 + concurrency gate + generic 500 + Content-Length fix→T9; single-worker gunicorn + retention lifespan→T10; Caddy tls-internal/auth/allowlist/file_server/proxy→T11; Docker + compose + future recorder placeholder→T12; n2disk reference templates + README→T13; verification→T14.
- **Deferred-by-design items** (SPEC v2 §15): exact npcapextract placement (noted in T12 Dockerfile comment + README), recorder containerization (compose placeholder + README), full HTTPS e2e (out of scope — validated by config review).
- **Type consistency:** `ParsedAlert` field names, `FILTER_MODES`/`VALID_FILTER_MODES`, `run_extraction` signature and result constants (`NO_BPF`/`ERR_TIMEOUT`/`ERR_FAILED`), and `Settings` field names are used identically across tasks.
- **Placeholder scan:** no TBD/TODO; every code step contains complete code. The one intentional test contradiction in T4 is called out with explicit fix instructions before the test is run.
