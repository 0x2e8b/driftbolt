# Sycope Traffic Recorder v2 — Design Specification

**Status:** Approved design, ready for implementation planning
**Date:** 2026-07-01
**Supersedes:** the legacy system in `old/` (behaviorally documented in `SPEC.md`)

This document specifies the **new architecture** for the Sycope Traffic
Recorder. It builds on `SPEC.md`, which is the authoritative *behavioral*
specification of the legacy system. Where this document says "preserve," the
precise rules live in the referenced `SPEC.md` section and must be copied
faithfully. Where this document says "change," it deliberately diverges from
legacy, and the divergence is called out so it is a documented decision rather
than a silent regression.

**Guiding principle:** maximum **stability and fault tolerance** over
concurrency/performance. This is a low-load, internal-network service. When a
design choice trades throughput for predictability or resilience, take the
resilient option.

---

## 1. Goals & Non-Goals

### 1.1 Goals

- Re-implement the alert → extract → serve pipeline as a modern, containerized
  Python service.
- **Preserve the Sycope-facing `/extract` request/response contract** so the
  Sycope webhook integration continues to work with, at most, updated
  credentials/URL/port (see §3).
- Run entirely under **Docker** (Docker Compose), built for stability, with the
  future **recorder (n2disk) container** able to join the stack later without a
  redesign.
- **Python environment managed by `uv`.**
- HTTP API built with **FastAPI**, served by **gunicorn with uvicorn workers**,
  fronted by **Caddy** as a reverse proxy that terminates **HTTPS**.
- Caddy ↔ app communication over a **unix socket file** where possible.
- Fix the safe, additive/internal defects catalogued in `SPEC.md` §12/§14
  (health endpoint, proxy awareness, error handling, logging, retention).

### 1.2 Non-Goals

- Reimplementing packet capture or extraction logic — `n2disk` and
  `npcapextract` remain external binaries (SPEC §3). This service is orchestration.
- High throughput / horizontal scaling / concurrent extraction beyond the
  configured cap.
- Building the recorder (n2disk) container in this project. Its config/unit
  templates are carried forward as reference (§9); its containerization and the
  exact placement of the `npcapextract` binary are decided when the recorder is
  integrated (§8.3).
- Porting the legacy `netflow_replay.py` demo tool (dropped — see §11).

---

## 2. Architecture Overview

Two containers now; a third (recorder) slots in later against the same volumes.

```
                       ┌──────────────────── docker compose network ────────────────────┐
 Sycope   ──HTTPS──►  caddy  (edge)                                                       
 Analyst  ──HTTPS──►    • TLS via internal CA (tls internal)                              
                        • Basic auth (single shared credential) + IP allowlist           
                        • GET  /downloads/*  ── file_server ──► [alerts volume] (read)    
                        • POST /extract   ─┐                                              
                        • GET  /           ├─ reverse_proxy ──► unix:/run/api/api.sock    
                        • GET  /healthz  ──┘   (/healthz unauthenticated)                 
                                                        │                                 
                                               api  (FastAPI)                             
                                               gunicorn + 1 uvicorn worker                
                                               bound to unix socket                       
                                                 • POST /extract → npcapextract (subproc) 
                                                 • retention sweep (async bg task)         
                                                 • writes ──► [alerts volume]              
                                                 • reads  ──► [rolling volume] (ro)        
                                                                                          
             (added later) recorder: n2disk ──► [rolling volume]  (capture + index)       
                       └─────────────────────────────────────────────────────────────────┘
```

### 2.1 Services

| Service | Role | Ports |
|---|---|---|
| `caddy` | TLS edge, auth + IP allowlist, static file server for downloads, reverse proxy for the API | Publishes `443` (and optionally `80`→redirect) to the host |
| `api` | FastAPI app (gunicorn/uvicorn) that handles `/extract`, help, health, and retention | **No published port**; listens only on a unix socket |
| `recorder` *(future)* | n2disk continuous capture + timeline index | none / host-network as required by n2disk |

### 2.2 Volumes

| Volume | Contents | Written by | Read by | Legacy path |
|---|---|---|---|---|
| `rolling` | Continuous rolling capture + n2disk timeline index | recorder (future) | `api`/npcapextract (read-only) | `/storage/pcaps/rolling` |
| `alerts` | Extracted per-alert PCAPs | `api` | `caddy` (file server) | `/storage/pcaps/alerts` |
| `run` | The unix socket file for caddy ↔ api | `api` | `caddy` | — |
| `caddy_data` | Caddy internal CA + state | `caddy` | `caddy` | — |

Mount rules:
- `api` mounts `rolling` **read-only** and `alerts` **read-write**.
- `caddy` mounts `alerts` **read-only** and `run` (socket) **read-only**.
- The `api` container **creates `alerts` on demand** (`makedirs(exist_ok=True)`)
  at startup and before each extraction (SPEC §4). `caddy` never creates it.

### 2.3 Container ↔ container communication

- **caddy → api:** `reverse_proxy unix//run/api/api.sock` over the shared `run`
  volume. No TCP between them.
- **api → recorder:** none directly. Coordination is filesystem-only (the
  `rolling` volume + `npcapextract` exit code / output file), exactly as legacy
  (SPEC §2). `npcapextract` availability in the `api` container is deferred
  (§8.3).

---

## 3. Compatibility Contract (what MUST be preserved)

Decision: **preserve the `/extract` request/response contract**; modernize
everything else. Concretely, the following are copied faithfully from `SPEC.md`:

- **Request surface (SPEC §5.2):** accept `POST` (route on `/extract`, but do
  not *require* Sycope to change its configured path — accept any POST path for
  legacy leniency). Query params `filter`, `before`, `after` with the same names,
  valid values, defaults, invalid-value fallback, and `[0, 86400]` clamping.
- **Alert JSON parsing (SPEC §5.3):** the full field-alias table and priority
  order for client IP, server IP, port, protocol, timestamp, id, name —
  including the ms-vs-seconds timestamp heuristic (`> 1e12`), the
  `%d.%m.%y %H:%M:%S` string fallback, `datetime.now()` final fallback, and the
  **presence-vs-truthiness asymmetry** between the flow fields and `id`/`name`.
- **BPF construction (SPEC §5.5):** the 5 fixed filter modes and their host/port
  inclusion, the ICMP-protocol-dropped-when-port-present rule, the port-term
  only-for-tcp/udp/unknown rule, and the "reject bare-protocol-only / empty →
  `None`" rule.
- **`npcapextract` invocation (SPEC §3.2, §5.4):** `-t -b -e -f -o`, timestamp
  format `%Y-%m-%d %H:%M:%S` (local), **300 s** timeout, no retry; success =
  `rc == 0` AND file exists AND size `> 0`.
- **MISS handling (decision — preserve):** a zero-byte result (rc 0, empty
  match) is logged distinctly as `MISS` server-side and the empty file deleted,
  but the **caller-facing response remains `ERROR: npcapextract failed`** so
  Sycope's existing handling is unchanged (SPEC §3.2, §12.3). *We do not add a
  distinct empty-match response string.*
- **Filename scheme (SPEC §5.4):** `{alert_time:%Y%m%d_%H%M%S}_{safe_id}.pcap`
  with the same id sanitization (alnum + `-`/`_`, 64-char cap, `"alert"`
  fallback) and flat output directory.
- **Response semantics (SPEC §5.2):** every post-validation `/extract` outcome
  returns **HTTP 200**, `Content-Type: text/plain`, an `X-Result` header
  duplicating the body, and body ∈ { download URL, `NO BPF FILTER`,
  `ERROR: npcapextract timeout`, `ERROR: npcapextract failed` }.
- **Help endpoint (SPEC §5.6):** `GET /` returns the same JSON shape
  (`status: "ok"`, `usage`, `examples`).

### 3.1 Deliberate divergences from legacy (documented)

| Area | Legacy | v2 | Reason |
|---|---|---|---|
| Returned download URL | `http://{host}:{fileserver_port}/{filename}` | `https://{public_host}/{download_prefix}/{filename}` (host from config) | HTTPS via Caddy; single edge port |
| TLS | none | Caddy `tls internal` (self-signed CA) | "guarantee https" |
| Auth & IP allowlist | in the two Python apps, two credential pairs | **in Caddy**, single shared credential | Edge owns access control (§6) |
| File serving | `fileserver.py` (Python) | Caddy `file_server` | Stability — downloads never touch Python |
| Config | `config/config.json`, hardcoded path | pydantic-settings (env + optional file) | Container-friendly, typed, fail-fast (§7) |
| Health | none (help endpoint behind auth) | unauthenticated `GET /healthz` | Docker healthcheck / monitoring |
| Retention | none | age + size-cap sweep | Bounded disk use (§10) |
| Proxy awareness | none (raw TCP peer) | trusted-proxy / XFF-aware client IP in logs | App is always behind Caddy |
| `500` body | raw exception string | generic message; detail logged server-side | No info leak |
| `Content-Length` | non-numeric → dropped connection | clean `400` | Robustness (SPEC §12.14) |
| Deployment | systemd on host | Docker Compose | Requirement |
| Runtime | stdlib `http.server` on Python 3.7 | FastAPI on a current Python (3.12+) under gunicorn/uvicorn, uv-managed | Requirement |

> Because auth moves to Caddy, the app itself no longer issues `401`. Caddy
> returns `401`/`403` for auth/allowlist failures before the request reaches the
> app. The `429` concurrency response and the request-body validation codes
> (`411`/`413`/`400`) remain app responsibilities (§5.3).

---

## 4. Configuration (`config.py`, pydantic-settings)

Typed settings loaded once at startup from **environment variables** (primary,
container-friendly) with an **optional file** override; validated eagerly so the
process **fails fast** on bad/missing required config (matches the legacy
fail-fast intent, SPEC §7, without the hardcoded path).

### 4.1 Settings

| Setting | Type | Default | Required | Notes |
|---|---|---|---|---|
| `public_host` | str | — | yes | Externally reachable host/domain used to build the returned `https://` download URL. Replaces legacy `host`. |
| `download_prefix` | str | `downloads` | no | URL path segment under which Caddy serves the alerts dir. Returned URL = `https://{public_host}/{download_prefix}/{filename}`. |
| `timeline_dir` | path | `/storage/pcaps/rolling` | yes | Passed to `npcapextract -t`; the rolling volume with its index. |
| `output_dir` | path | `/storage/pcaps/alerts` | yes | Extraction output; also what Caddy serves. |
| `default_filter` | str | `full` | yes | One of the 5 mode names; unknown falls back to `full` at use-time (double safety net, SPEC §8). |
| `default_before` | int (s) | `360` | yes | Fallback for missing/invalid `before` query param. |
| `default_after` | int (s) | `360` | yes | Fallback for missing/invalid `after` query param. |
| `max_concurrent_extractions` | int | `1` | no | Min-clamped to `1`. Global extraction gate (§5.4). |
| `extract_timeout_seconds` | int | `300` | no | `npcapextract` subprocess timeout. Preserve `300` unless deliberately changed. |
| `npcapextract_path` | str | `npcapextract` | no | Binary name/path; resolved on `PATH` by default. |
| `retention_max_age_days` | int | `7` | no | Delete extracted PCAPs older than this. `0` disables age-based deletion. |
| `retention_max_total_bytes` | int | `0` | no | Size ceiling for `output_dir`; oldest-first deletion when exceeded. `0` disables the size cap. |
| `retention_interval_seconds` | int | `3600` | no | Sweep cadence. |
| `log_level` | str | `INFO` | no | — |
| `log_format` | str (`text`\|`json`) | `text` | no | Unified logging (§12). |
| `trusted_proxies` | list[str] | `[]` | no | CIDRs/IPs whose `X-Forwarded-For` is trusted for client-IP resolution in logs (Caddy). |

Auth credentials and the file-download IP allowlist are **not** app settings in
v2 — they are configured in Caddy (§6). The legacy `config.json` keys and the
`basic_auth_*` shim are **not** carried into the app (documented divergence,
§3.1); operators migrate to env/Caddy config.

### 4.2 Validation rules

- Missing any required setting → log a clear error and exit non-zero at startup.
- `default_filter` not one of the 5 modes → warn and treat as `full`.
- Numeric settings out of range → clamp with a warning (`max_concurrent_extractions ≥ 1`;
  `before`/`after` at request time to `[0, 86400]`).

---

## 5. API Component (`api.py` / `main.py`)

FastAPI application, single worker (see §8.2), no auth in-app (Caddy owns it).

### 5.1 Endpoints

| Method / path | Auth (at Caddy) | Purpose |
|---|---|---|
| `POST /extract` (and any POST path, for leniency) | Basic auth (+ optional IP allowlist) | The webhook: parse alert, extract, return URL/status string |
| `GET /` | Basic auth | Preserved help JSON (SPEC §5.6): `status`/`usage`/`examples` |
| `GET /healthz` | **none** | Liveness/readiness for Docker healthcheck & monitoring |

### 5.2 `/healthz`

Returns `200` with a small JSON body (e.g. `{"status": "ok"}`) when the process
is up and the event loop is responsive. It does **not** run an extraction. It
**may** include lightweight readiness signals (e.g. whether `timeline_dir` and
`output_dir` are present) as non-fatal informational fields; presence problems
are logged but do not, by themselves, fail startup (matching legacy tolerance,
SPEC §5.1). Because extractions run in a threadpool (§8.2), `/healthz` stays
responsive even during a long extraction.

### 5.3 `/extract` request handling

Order of checks (each short-circuits), preserving SPEC §5.2 semantics minus the
now-Caddy-owned auth:

1. **`Content-Length` missing** → `411`, body `Missing Content-Length`.
2. **`Content-Length` non-numeric** → `400` (fix for SPEC §12.14; legacy dropped
   the connection).
3. **`Content-Length > 2 MiB`** → `413`, body `Payload too large`. Hard cap.
4. **Empty body** → `400`, body `Empty request body`.
5. **Invalid JSON** → `400`, body `Invalid JSON` (parse error logged
   server-side; raw body not returned).
6. **Concurrency gate** (§5.4) → if not acquirable, `429` + `Retry-After: 5`,
   body `Too many concurrent extractions`.
7. Otherwise parse alert (§3), build BPF, run extraction, return **200** with
   the outcome string (§3 response semantics).
8. **Any unexpected exception** → `500` with a **generic** body (e.g.
   `Internal error`); the exception detail is logged server-side only (fix for
   SPEC §11 info leak).

Per-request INFO logging preserves the legacy detail (SPEC §5.2): separator
line, alert id/name, alert JSON top-level keys, effective params, parsed
local+UTC alert time, resolved flow tuple; warn (but proceed) if an IP is
missing. UTC logging uses a timezone-aware API (not the deprecated
`datetime.utcfromtimestamp`, SPEC §12.13).

### 5.4 Concurrency gate

A single global `asyncio.Semaphore(max_concurrent_extractions)` (default `1`)
guards **only** the `npcapextract` call, not the whole request. Non-blocking
acquire; on failure → `429` (§5.3.6). Released in `finally` regardless of
outcome. Validity of the global gate depends on the **single-worker** model
(§8.2).

---

## 6. Edge Component (Caddy)

A single `Caddyfile`. Responsibilities:

- **TLS:** `tls internal` — Caddy's internal CA issues a self-signed cert. (The
  Caddy internal CA root is what Sycope/clients must trust, or verification is
  skipped on their side.) `caddy_data` volume persists the CA across restarts.
- **Authentication:** HTTP **Basic auth with a single shared credential**
  (bcrypt-hashed in the Caddyfile / via env) applied to `POST /extract`,
  `GET /`, and `GET /downloads/*`. `GET /healthz` is **excluded** (unauthenticated).
- **IP allowlist:** `remote_ip` matcher.
  - **Downloads** (`/downloads/*`): allowlist enforced (preserves legacy
    fileserver allowlist, SPEC §6). Empty list = allow all.
  - **`/extract`:** optional allowlist for Sycope's source IP (adds the listener
    allowlist that legacy lacked, SPEC §12.8/§14). Configurable; default allow all.
  - Caddy sees the real client IP directly (it is the edge); `trusted_proxies`
    (§4.1) is only relevant if another proxy sits in front of Caddy.
- **File serving** (`GET /downloads/*`): `file_server` rooted at the `alerts`
  volume (read-only mount). **Directory listing disabled** (`browse` off) —
  only exact known filenames are servable (preserves SPEC §6). `404` for
  unknown files.
- **Reverse proxy:** `POST /extract`, `GET /`, `GET /healthz` →
  `reverse_proxy unix//run/api/api.sock`.
- **Redirect:** optional `:80` → `:443` redirect.

> Rationale: serving downloads directly from Caddy keeps the (potentially large)
> file transfers entirely out of the Python process, which is the single biggest
> stability win — a slow/aborted download can never tie up the extraction path.

---

## 7. Extraction Pipeline (`extraction.py`, `alert.py`, `bpf.py`)

Faithful re-implementation of SPEC §5.3–§5.5, factored into pure, independently
testable units:

- **`alert.parse_alert(payload) -> ParsedAlert`** — the alias table + fallback
  logic (SPEC §5.3). Pure function of the JSON dict; no I/O.
- **`bpf.build_bpf_filter(parsed, mode) -> str | None`** — the term-selection
  algorithm and rejection rule (SPEC §5.5). Pure.
- **`extraction.compute_window(alert_time, before, after)`** and
  **`extraction.build_filename(alert_time, alert_id)`** — window formatting and
  filename/sanitization (SPEC §5.4). Pure.
- **`extraction.run_extraction(parsed, mode, before, after) -> str`** — the
  orchestrator: `makedirs`, build filter (early `NO BPF FILTER` return with no
  subprocess), build command, run `npcapextract` in a **threadpool executor**
  (blocking subprocess kept off the event loop), classify success/MISS/timeout/
  failure, log outcomes (SPEC §5.4 log lines), and return the response string
  (download URL on success). The subprocess call sets the configured timeout and
  captures stdout/stderr for server-side logging only.

Pure functions take no config directly; config is injected (defaults, dirs,
binary path) so tests can exercise them in isolation.

---

## 8. Runtime, Packaging & Docker

### 8.1 Packaging (`uv`)

- `pyproject.toml` + `uv.lock`; dependencies: `fastapi`, `uvicorn[standard]`,
  `gunicorn`, `pydantic`, `pydantic-settings`. Dev group: `pytest`,
  `pytest-asyncio`, `httpx` (test client), linter/formatter (`ruff`), type
  checker (`mypy`) as chosen during planning.
- `src/` layout, package `sycope_recorder`.

### 8.2 Process model (stability-first)

- **gunicorn** with the **uvicorn worker class**, **1 worker**. gunicorn
  provides master supervision + graceful worker restarts; Docker
  `restart: unless-stopped` supervises the container.
- 1 worker + async endpoints keeps the global concurrency semaphore (§5.4) and
  the single-runner retention task (§10) correct without cross-process
  coordination.
- Blocking `npcapextract` runs in a threadpool so the event loop (health,
  concurrent request rejection) stays responsive during the up-to-300 s
  extraction.
- **gunicorn worker timeout set above `extract_timeout_seconds`** (e.g. 330 s)
  so a legitimate long extraction is never killed by gunicorn; graceful-timeout
  configured accordingly. Config in `gunicorn.conf.py`.
- gunicorn binds the **unix socket** (`unix:/run/api/api.sock`) with appropriate
  permissions for the Caddy container to connect.

### 8.3 `npcapextract` availability (deferred)

Per decision, the API is specified assuming `npcapextract` is resolvable on
`PATH` (or via `npcapextract_path`) and the `rolling`/`alerts` volumes are
mounted. The **exact placement of the binary** (bundled into the API image vs.
invoked in the recorder container) is decided when the recorder is integrated
into Docker. The code depends only on: (a) the binary being invokable as a
subprocess, and (b) shared filesystem access to the volumes — so either
placement is accommodated without code changes.

### 8.4 Docker artifacts

- **`Dockerfile`** (api): uv-based build (install locked deps into the image),
  non-root user where feasible (must retain read access to the n2disk-owned
  rolling data — the `ntop`-group gotcha from SPEC §3.1/§9 applies via
  volume/user mapping and is documented for the future recorder integration),
  runs gunicorn per §8.2. `HEALTHCHECK` hits `/healthz` **through the app**
  (e.g. via the socket or an internal check).
- **`compose.yaml`**: `caddy` + `api` services, the four volumes (§2.2),
  `restart: unless-stopped` on both, Caddy publishing `443` (+ optional `80`),
  `api` publishing nothing. A commented placeholder documents where the future
  `recorder` service attaches (shared `rolling` volume, capture privileges).
- **`caddy/Caddyfile`** per §6.
- **`gunicorn.conf.py`** per §8.2.

---

## 9. Reference Material Carried Forward

- `docs/reference/n2disk.conf` and `docs/reference/n2disk.service` — copied from
  `old/config/` as **templates/reference** for the future recorder container
  (SPEC §3.1, §9). Not installed or used by the v2 API; documented as the
  starting point for recorder integration.
- `SPEC.md` remains the authoritative behavioral reference for the preserved
  logic and is cross-referenced throughout this document.

---

## 10. Retention (`retention.py`)

An **async background task** started with the app (single worker → runs exactly
once). Every `retention_interval_seconds` it sweeps `output_dir`:

1. **Age:** delete files older than `retention_max_age_days` (skip if `0`).
2. **Size cap:** if total size of `output_dir` exceeds
   `retention_max_total_bytes` (skip if `0`), delete **oldest-first** until under
   the ceiling.

Only regular `*.pcap` files in the flat `output_dir` are considered. Deletions
are logged (count + bytes reclaimed). Failures to stat/delete an individual file
are logged and skipped — the sweep never crashes the app (fault tolerance). This
bounds disk use that the legacy system left entirely to the operator (SPEC
§12.12), complementing n2disk's own `--disk-limit` on the rolling dir.

---

## 11. Dropped from Legacy

- **`netflow_replay.py`** — the NetFlow demo/replay tool is **not** ported (its
  `dpkt` dependency and hardcoded constants are demo-only; SPEC §10). If e2e
  alert injection is needed later it can be reintroduced as a separate dev tool.
- **`config.json` + hardcoded config path + `basic_auth_*` shim** — replaced by
  pydantic-settings (§4) and Caddy-managed auth (§6).
- **`fileserver.py`** — replaced by Caddy `file_server` (§6).
- **systemd units for the Python services** — replaced by Docker Compose (§8.4).

---

## 12. Logging & Observability

- **Unified logging config** (`logging.py`) for the whole app: one formatter and
  handler set to stdout (Docker/journal captures it), configurable level and
  `text`/`json` format (§4.1). No stray `print()` or separate access-log stream
  (fixes SPEC §12.5/§12.15).
- FastAPI/uvicorn access logging routed through the same config (or suppressed in
  favor of the app's structured per-request line, matching legacy's suppressed
  access log, SPEC §5.1).
- Per-`/extract` request log preserves the legacy detail set (§5.3).
- Extraction outcomes log `SUCCESS`/`MISS`/timeout/failure distinctly
  server-side (the MISS/failure *response* remains merged per §3).
- Caddy logs at the edge (access + TLS) via its own config.

---

## 13. Testing Strategy (TDD)

Tests are written before implementation, per unit.

### 13.1 Unit tests (pure logic)

- **Alert parsing** (`alert.py`): every alias, priority order, first-match
  semantics, ms-vs-seconds heuristic, string-timestamp fallback, `datetime.now()`
  fallback, and the `id`/`name` presence-vs-truthiness asymmetry (incl. the
  `id: null → "None"` case). Table-driven against SPEC §5.3.
- **BPF construction** (`bpf.py`): all 5 modes × presence/absence of each field;
  the ICMP-drop-when-port and port-only-for-tcp/udp/unknown rules; the
  bare-protocol/empty rejection → `None`. Table-driven against SPEC §5.5.
- **Window & filename** (`extraction.py`): window formatting, `before`/`after`
  clamping, filename pattern, id sanitization (alnum + `-`/`_`, 64-cap,
  `"alert"` fallback).
- **Config** (`config.py`): required-missing → fail; range clamping; bad
  `default_filter` → `full`.
- **Retention** (`retention.py`): selection logic for age and oldest-first
  size-cap deletion (using temp dirs / fake mtimes).

### 13.2 Integration tests (`/extract` end-to-end within the app)

- Drive the FastAPI app with `httpx`/TestClient against a **stub `npcapextract`
  binary** (a small script placed on `PATH` via `npcapextract_path`) that:
  - asserts the exact CLI shape (`-t -b -e -f -o`, timestamp format),
  - simulates each outcome: **success** (writes a non-empty file, rc 0),
    **MISS** (rc 0, zero-byte file), **failure** (non-zero rc), **timeout**
    (sleeps past the configured timeout — use a shortened `extract_timeout_seconds`).
- Assert the response contract for each: `200` + correct body string / URL,
  `X-Result` header, and the request-validation codes (`411`/`400`/`413`) and
  `429` concurrency behavior.
- Assert `/healthz` is reachable without auth and responds during a simulated
  long extraction (event-loop responsiveness).

No real `n2disk`/`npcapextract` is required in CI.

### 13.3 Out of scope for automated CI

Full Docker/Caddy HTTPS e2e (booting the compose stack and exercising it through
TLS) is **not** part of the automated suite for this iteration (per decision).
Auth, TLS, IP allowlist, and file serving are Caddy responsibilities validated
by configuration review and manual verification.

---

## 14. Project Layout (proposed)

```
sycope_recorder/
├── pyproject.toml            # uv-managed project + deps
├── uv.lock
├── Dockerfile                # api image
├── compose.yaml              # caddy + api (+ future recorder placeholder)
├── gunicorn.conf.py          # 1 uvicorn worker, unix socket, timeout > extract
├── caddy/
│   └── Caddyfile             # TLS internal, auth, allowlist, file_server, reverse_proxy
├── src/sycope_recorder/
│   ├── __init__.py
│   ├── main.py               # app factory + lifespan (starts retention task)
│   ├── api.py                # routes: /extract, /, /healthz
│   ├── config.py             # pydantic-settings
│   ├── alert.py              # parse_alert (pure)
│   ├── bpf.py                # build_bpf_filter + filter modes (pure)
│   ├── extraction.py         # window/filename (pure) + run_extraction (subprocess)
│   ├── retention.py          # age + size-cap sweep
│   └── logging.py            # unified logging config
├── tests/
│   ├── unit/                 # alert, bpf, extraction-pure, config, retention
│   ├── integration/          # /extract against stub npcapextract
│   └── stubs/npcapextract    # fake binary for integration tests
└── docs/
    ├── reference/
    │   ├── n2disk.conf        # carried forward as recorder template
    │   └── n2disk.service     # carried forward as recorder template
    └── superpowers/specs/
        └── 2026-07-01-sycope-recorder-v2-design.md   # this document
```

Final module boundaries and file names are confirmed during implementation
planning; each unit has a single clear purpose, a defined interface, and is
testable in isolation.

---

## 15. Open Items Deferred (by explicit decision)

- Exact placement/bundling of the `npcapextract` binary (API image vs. recorder
  container) — decided at recorder integration (§8.3).
- Recorder (n2disk) containerization, capture privileges, and network mode —
  future work; templates carried forward (§9).
- Full Docker/HTTPS e2e automation — out of scope this iteration (§13.3).
