"""FastAPI app: the Sycope alert webhook listener.

Exposes the `/extract` endpoint that Sycope's webhook action calls on
alert firing, plus `/healthz` and a help page at `/`. The webhook handler
always returns HTTP 200 for extraction outcomes (success or failure),
using only the response body text (and a duplicate `X-Result` header) to
signal which — Sycope's webhook consumer parses body text, not status
code, so this can't be changed without breaking the legacy contract (see
SPEC.md §5.2). Only pre-extraction validation failures (bad
Content-Length, bad JSON, concurrency limit) use non-200 statuses.

App lifespan starts/stops the retention background loop alongside the
extraction request-handling routes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from sycope_recorder.alert import parse_alert
from sycope_recorder.config import Settings, VALID_FILTER_MODES
from sycope_recorder.extraction import run_extraction
from sycope_recorder.retention import retention_loop

log = logging.getLogger("sycope_recorder")

MAX_BODY_BYTES = 2 * 1024 * 1024
CLAMP_MIN, CLAMP_MAX = 0, 86400


def _help_body(settings: Settings) -> dict:
    """Build the JSON body for the `/` help endpoint, echoing the caller's effective defaults."""
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
    """Build and wire up the FastAPI app: routes, per-app state, and the retention lifecycle.

    `start_retention=False` exists so tests can build an app without a
    background retention task running against real timers/filesystem
    state.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run the retention loop as a background task for the app's lifetime, cancelling it cleanly on shutdown."""
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
                except asyncio.CancelledError:
                    pass  # expected: we just cancelled the task
                except Exception:
                    log.warning("retention task raised during shutdown", exc_info=True)

    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.settings = settings
    app.state.active_extractions = 0  # single-worker gate; no lock needed

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Report whether the configured timeline/output directories are mounted, for container/orchestrator liveness checks."""
        return JSONResponse(
            {
                "status": "ok",
                "timeline_dir_present": os.path.isdir(settings.timeline_dir),
                "output_dir_present": os.path.isdir(settings.output_dir),
            }
        )

    @app.get("/")
    def help_endpoint() -> JSONResponse:
        """Serve usage info at the root path, since docs/openapi routes are disabled above."""
        return JSONResponse(_help_body(settings))

    def _resolve_params(request: Request) -> tuple[str, int, int]:
        """Resolve filter/before/after query params, falling back to configured defaults (with a warning logged) on anything missing or unparseable rather than rejecting the request."""
        q = request.query_params
        mode = q.get("filter") or settings.default_filter
        if mode not in VALID_FILTER_MODES:
            log.warning("unknown filter mode %r; using %s", mode, settings.default_filter)
            mode = settings.default_filter if settings.default_filter in VALID_FILTER_MODES else "full"

        def _int(name: str, default: int) -> int:
            """Parse one integer query param, clamped to [CLAMP_MIN, CLAMP_MAX]; falls back to `default` if absent or not an int."""
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
        """Handle the Sycope alert webhook: validate, parse, extract, respond.

        Routed as a catch-all on any POST path (not just `/extract`)
        because the legacy listener never inspected the request path at
        all — Sycope's configured webhook URL must keep working
        regardless of exact path.

        Validation order is deliberate and each step short-circuits with
        a specific status, checked in this sequence: Content-Length
        present, Content-Length within MAX_BODY_BYTES, body non-empty,
        body is valid JSON, concurrency slot available. Content-Length is
        checked before the body is even read so oversized/missing-header
        requests are rejected without paying for a read, and JSON parsing
        happens before the concurrency gate so a malformed request never
        occupies an extraction slot.

        The concurrency gate wraps only the extraction call, not the
        whole request — validation and parsing above it are cheap and
        shouldn't compete for the limited extraction slots that guard the
        expensive npcapextract subprocess. `active_extractions` is a
        plain counter rather than a lock/semaphore because this app runs
        single-worker, so there's no cross-worker or cross-thread race to
        guard against.

        Once validation passes, every outcome — a real download URL, "NO
        BPF FILTER", or an npcapextract timeout/failure string — is
        reported as HTTP 200, with the result string duplicated into the
        X-Result header. This matches the legacy contract: Sycope's
        webhook consumer distinguishes success from failure by reading
        the body text, not the status code (see SPEC.md §5.2).

        The final bare `except Exception` returns a generic "Internal
        error" 500 without the exception text, unlike the legacy listener
        which leaked `str(exception)` to the caller — an intentional
        hardening, not an oversight; the real error is only logged
        server-side.
        """
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
        app.state.active_extractions += 1

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

            result = await asyncio.get_running_loop().run_in_executor(
                None, run_extraction, parsed, mode, before, after, settings
            )

            return PlainTextResponse(result, headers={"X-Result": result})
        except Exception:  # generic 500, no detail leak
            log.exception("unhandled error during extraction")
            return PlainTextResponse("Internal error", status_code=500)
        finally:
            app.state.active_extractions -= 1

    return app
