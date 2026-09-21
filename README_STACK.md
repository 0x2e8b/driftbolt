# Technology Stack

This document explains **what** the service is built from, **why** each piece
was chosen, **how** the pieces connect, and **why** the default configuration
values are what they are. For request/response behavior see `SPEC.md`; for
the full design rationale see
`docs/superpowers/specs/2026-07-01-sycope-recorder-v2-design.md`, which this
document summarizes and complements.

The guiding principle behind every choice below: this is a **low-load,
internal-network service** triggered by alerts, not a high-traffic public API.
Wherever a decision trades throughput/concurrency for predictability,
simplicity, or fault tolerance, we take the resilient option.

## At a glance

| Layer | Technology | Role |
|---|---|---|
| Package/dependency management | **uv** | Locked, reproducible Python environment |
| Language/runtime | **Python 3.12** | App language |
| Web framework | **FastAPI** (+ **pydantic**) | Routing, request validation, async endpoints |
| Application server | **gunicorn** with the **uvicorn worker class** | Process supervision + ASGI serving |
| Configuration | **pydantic-settings** | Typed, env-driven, fail-fast config |
| Edge / reverse proxy | **Caddy 2** | TLS, auth, IP allowlisting, static file serving |
| Transport (app ↔ edge) | **Unix domain socket** | Caddy ↔ gunicorn IPC |
| Packaging/deployment | **Docker** + **Docker Compose** | Containerization and orchestration |

## How a request flows through the stack

```
Sycope / analyst
      │  HTTPS
      ▼
   Caddy (edge container)
      │  TLS termination, Basic auth, IP allowlist
      │  • GET  /downloads/*  → served directly by Caddy's file_server
      │  • GET  /healthz      → proxied, unauthenticated
      │  • everything else    → reverse_proxy over a unix socket
      ▼
   gunicorn (1 worker, uvicorn worker class)
      │  ASGI protocol
      ▼
   FastAPI app (sycope_recorder.main:app)
      │  parse alert → build BPF filter → run npcapextract (in a threadpool)
      ▼
   npcapextract (external subprocess) → writes PCAP to the alerts volume
```

Caddy and the app never talk over TCP; they share a `run` volume containing
`api.sock`. Caddy also mounts the `alerts` volume read-only so it can serve
extracted PCAPs without the file ever passing through Python.

---

## Component-by-component

### uv — dependency and environment management

**What:** `uv` resolves and locks dependencies (`pyproject.toml` + `uv.lock`)
and manages the virtualenv, both locally and inside the Docker build.

**Why chosen:**
- Deterministic, lockfile-based installs (`uv sync --frozen`) mean the exact
  same dependency versions run in dev, CI, and production — no
  "works on my machine" drift.
- It's fast enough that `uv sync` inside the Docker build doesn't meaningfully
  slow down image builds, and it installs both the app's runtime dependencies
  and its dev/test tooling (`pytest`, `ruff`) from one lockfile via dependency
  groups, so there's a single source of truth for versions.
- Single static binary, no separate Python-version-manager dependency — the
  `Dockerfile` copies the `uv` binary directly from its own published image
  (`COPY --from=ghcr.io/astral-sh/uv:latest /uv ...`).

**Default/config notes:**
- The Dockerfile runs `uv sync --frozen --no-dev --no-install-project` for
  dependencies *before* copying source (better Docker layer caching — deps
  rarely change, source changes every build), then a second
  `uv sync --frozen --no-dev` once the source is in place. `--frozen` refuses
  to update `uv.lock`, so a stale lock fails the build loudly instead of
  silently drifting from what's committed.
- `.python-version` pins the interpreter uv provisions, matching the
  `python:3.12-slim` base image.

### Python 3.12 + FastAPI + pydantic

**What:** The app itself (`src/sycope_recorder/`) is a FastAPI application.
Pydantic models validate the alert payload shape where useful; hand-written
parsing (`alert.py`) handles the intentionally loose, legacy-compatible alert
JSON that doesn't fit a strict schema (see `SPEC.md` §5.3).

**Why chosen:**
- FastAPI is ASGI-native, so the single slow, blocking part of this service —
  the up-to-300-second `npcapextract` subprocess — can be pushed into a
  threadpool executor (`extraction.py`) while the event loop keeps serving
  `/healthz` and rejecting over-capacity `/extract` requests. A synchronous
  framework would need multiple processes/threads to get the same
  responsiveness.
- Async support pairs naturally with a single global `asyncio.Semaphore` as
  the concurrency gate for extractions (see gunicorn's single-worker note
  below) — no cross-process coordination (Redis, file locks) needed.
- Typed request/response handling and automatic validation reduce
  hand-rolled parsing code versus the legacy `http.server`-based
  implementation, without changing the wire contract Sycope depends on.
- Mature, boring, widely deployed — appropriate for a service whose priority
  is stability over cutting-edge features.

**Default/config notes:**
- The app is constructed **eagerly at import time** in `main.py` (settings
  loaded, logging configured, app built) rather than lazily on first request.
  A misconfigured deployment fails at process start with a readable message,
  not on the first incoming webhook call.

### pydantic-settings — configuration

**What:** `config.py` defines a `Settings` model populated from `SR_`-prefixed
environment variables (`pydantic_settings.BaseSettings`).

**Why chosen:**
- Container-friendly: environment variables are the natural configuration
  surface for Docker/Compose, replacing the legacy hardcoded
  `config/config.json` path.
- Typed and validated eagerly — `get_settings()` either returns a valid
  `Settings` instance or exits the process with a one-line stderr message
  (`ERROR: invalid configuration: ...`), never a raw traceback. Fail-fast at
  startup is strictly better than failing on the first request.
- Where the legacy config loader silently clamped or defaulted bad values
  (e.g. `max_concurrent_extractions <= 0`, an unrecognized `default_filter`),
  the same "safety net" behavior is preserved via `field_validator`s rather
  than hard failures — matching operator expectations from the legacy system.

**Default/config notes:**
- `public_host` is the only setting with no default (`Settings()` fails
  without it) — every other setting has a legacy-compatible default so the
  service is usable out of the box.
- Auth credentials and the download IP allowlist are **not** app settings —
  they live in Caddy (see below). This keeps access control at the edge,
  where it can reject a request before it ever reaches Python.

### gunicorn + uvicorn worker class — application server

**What:** `gunicorn.conf.py` configures gunicorn to run **one** worker of
class `uvicorn.workers.UvicornWorker`, bound to a unix socket.

**Why chosen:**
- gunicorn is the process supervisor: it can restart a crashed worker without
  the whole container restarting, and it handles graceful shutdown/reload.
  uvicorn alone doesn't supervise; gunicorn alone can't speak ASGI — the
  combination gets both.
- **Exactly one worker** is a deliberate stability choice, not a
  not-yet-scaled default. The app relies on a single in-process
  `asyncio.Semaphore` to cap concurrent `npcapextract` invocations, and on a
  single retention background task running exactly once. Both invariants
  hold only under one worker/one process. This is a low-load service — one
  worker is not a bottleneck here, and adding workers would require
  re-architecting the concurrency gate around shared state (e.g. a
  file lock or external coordinator) for no real throughput benefit.
- Binding to a **unix socket** rather than a TCP port means the app is not
  independently reachable at all — only Caddy, which shares the socket's
  volume, can talk to it. There's no "forgot to firewall the app port"
  failure mode.

**Default/config notes:**
- `workers = 1` (see above — do not raise without redesigning the
  concurrency gate and retention task).
- `timeout` defaults to **330 seconds**, deliberately set *above*
  `SR_EXTRACT_TIMEOUT_SECONDS` (default 300s). gunicorn kills a worker that
  doesn't respond within `timeout`; if this were ≤ the extraction timeout, a
  legitimate long-running extraction could be killed by gunicorn before
  `npcapextract`'s own timeout even fires. The 30-second margin is
  intentional slack, not an arbitrary round number.
- `graceful_timeout` (default 30s) bounds how long gunicorn waits for
  in-flight requests to finish on shutdown/reload before force-killing the
  worker.
- `accesslog = None` — request logging is handled by the app's own
  structured per-request log line (`logging_config.py`), not gunicorn's
  separate access log stream. One log stream to stdout is easier to operate
  than two independently-formatted ones.

### Caddy — edge, TLS, auth, and static file serving

**What:** A single `caddy/Caddyfile` running as its own container, the only
one with published ports (`443`, `80`).

**Why chosen:**
- **TLS termination at the edge, not in the app.** `tls internal` makes
  Caddy its own certificate authority and auto-issues/renews a cert — no
  manual cert management for an internal-network service that doesn't need a
  publicly-trusted CA. This satisfies the "guarantee HTTPS" requirement with
  near-zero operational overhead. The generated CA persists across restarts
  via the `caddy_data` volume.
- **Auth and IP allowlisting live in Caddy, not in Python.** The legacy
  system implemented Basic auth and IP filtering twice, independently, in two
  Python services, with two separate credential pairs. Centralizing this at
  the edge means there is exactly one place access control is enforced, one
  shared credential, and the app can trust that anything reaching it over the
  unix socket already passed those checks.
- **Static file serving is Caddy's job, not FastAPI's.** Extracted PCAPs can
  be large; serving them from Python would tie up the same process (and,
  under one worker, the same event loop) responsible for triggering new
  extractions and answering health checks. Caddy's `file_server` serves
  files directly from the read-only `alerts` volume mount — a slow or
  aborted download can never affect extraction. This is called out
  explicitly in the design doc as "the single biggest stability win."
- **Request body size capping at the edge.** Caddy's `request_body { max_size
  2MiB }` is the *authoritative* enforcement of the 2 MiB `/extract` payload
  cap — it rejects an oversized body regardless of what `Content-Length`
  claims (or omits). The app also checks `Content-Length` itself, but only as
  a cheap early rejection; Caddy is the real backstop.
- Caddy's config format (the Caddyfile) is compact enough that all of the
  above — TLS, two independent auth blocks, an IP-based matcher, a file
  server, and a reverse proxy — fits in ~40 lines and stays readable.

**Default/config notes:**
- `admin off` — the Caddy admin API is disabled; nothing in this deployment
  needs Caddy's dynamic config API, and leaving it on would be an unused
  attack surface.
- `GET /healthz` is proxied **without** auth, deliberately — it's what Docker
  healthchecks and external monitoring hit, and requiring credentials there
  would complicate both for no security benefit (it reveals only liveness).
- The IP allowlist (`ALLOWED_IPS`, via `remote_ip`) defaults to
  `0.0.0.0/0 ::/0` (allow all) — restricting it is an explicit opt-in via
  environment variable, since not every deployment has a fixed set of
  Sycope/analyst source IPs to allow.
- `browse off` on the downloads `file_server` disables directory listing —
  only exact, known filenames are servable; there is no way to enumerate
  what's in the `alerts` volume.
- Basic auth uses a **single shared credential** (bcrypt hash, generated via
  `caddy hash-password`) rather than per-client credentials — this matches
  the trust model (Sycope and analysts are both "internal, authorized
  callers") and avoids credential-management complexity the deployment
  doesn't need.

### Unix domain socket — Caddy ↔ app transport

**Why chosen:** Caddy and the app run in separate containers but share a
Docker volume (`run`) containing `api.sock`. A unix socket avoids exposing
the app on any TCP port — even one restricted to the Docker network — and
has slightly lower overhead than loopback TCP. It also makes the trust
boundary explicit: the only way to reach the app is through the file
descriptor Caddy already holds.

**Default/config notes:** The app mounts `run` read-write (it creates and
binds the socket); Caddy mounts the same volume read-only.

### Docker + Docker Compose — packaging and orchestration

**Why chosen:**
- A hard requirement of the redesign, but also a good fit: it replaces
  per-host systemd units (legacy) with a portable, declarative stack that a
  future `recorder` (n2disk) service can join without redesigning anything —
  it would simply attach to the existing `rolling` volume.
- Named volumes (`rolling`, `alerts`, `run`, `caddy_data`, `caddy_config`)
  give each piece of state (capture data, extracted PCAPs, the IPC socket,
  Caddy's CA/state) an explicit owner and explicit read/write permissions per
  service, instead of ad hoc host paths.

**Default/config notes:**
- `restart: unless-stopped` on both services — the container runtime
  supervises the *process*; gunicorn's master process supervises the
  *worker*. Two levels of supervision, each responsible for a different
  failure mode (container crash vs. worker crash).
- The `api` service has **no published ports** — it is unreachable except
  through Caddy, by construction, not by firewall convention.
- The Docker `HEALTHCHECK` talks to the app **through the unix socket**
  directly (a small Python one-liner), not through Caddy — it needs to
  detect an unresponsive app process independent of whether Caddy itself is
  healthy.
- Required environment variables (`SR_PUBLIC_HOST`, `BASIC_AUTH_USER`,
  `BASIC_AUTH_HASH`) use Compose's `${VAR:?message}` syntax, which fails
  `docker compose up` immediately with a readable message if unset —
  consistent with the app's own fail-fast configuration philosophy, applied
  one layer up.
- The commented-out `recorder` service block in `compose.yaml` is
  intentionally left as a template rather than removed — n2disk needs host
  network mode and capture capabilities (`NET_RAW`/`NET_ADMIN`) that don't
  apply to `api`/`caddy`, and documenting the shape now avoids relitigating
  it when the recorder is integrated.

---

## Why not alternatives?

A few choices worth calling out explicitly, since they weren't the only
reasonable option:

- **Why not just uvicorn (no gunicorn)?** uvicorn alone can run multiple
  worker processes, but it doesn't supervise/restart them the way gunicorn's
  master process does. gunicorn + the uvicorn worker class gets ASGI serving
  with real process supervision.
- **Why not nginx instead of Caddy?** Caddy's `tls internal` gives automatic
  self-signed certificate management with zero extra tooling (no separate
  `openssl`/cert-bot step), and its config format expresses TLS + auth + IP
  matching + static serving + reverse proxy all in one small, readable file.
  For an internal service that doesn't need nginx's broader ecosystem, this
  is less to maintain.
- **Why not scale out workers/replicas for throughput?** This is explicitly
  a low-load, alert-triggered service, not a high-QPS API. The single-worker
  model buys correctness (one semaphore, one retention task, no cross-process
  coordination) at a cost the actual load profile never exercises.
