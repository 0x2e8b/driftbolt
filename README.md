# Sycope Traffic Recorder

Alert-triggered PCAP extraction service. Sycope sends a webhook, the service builds a BPF filter from the alert fields, runs `npcapextract` against the n2disk rolling capture, and returns a download URL for the matching packets.

![Python](https://img.shields.io/badge/python-3.12-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![Docker](https://img.shields.io/badge/docker-required-blue)
![n2disk](https://img.shields.io/badge/n2disk-required-orange)
![npcapextract](https://img.shields.io/badge/npcapextract-required-orange)

## Contents

- [Purpose](#purpose)
- [What's new in v2](#whats-new-in-v2)
- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Quickstart (Docker)](#quickstart-docker)
- [Sycope Webhook](#sycope-webhook)
- [Example Payload](#example-payload)
- [How It Works](#how-it-works)
- [Development](#development)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)

## Purpose

n2disk continuously records network traffic to rolling PCAP files (oldest files are overwritten automatically). When Sycope detects an alert, it POSTs the alert details (IPs, port, protocol, timestamp) to this service. The service builds a BPF filter from those fields and runs `npcapextract` against the rolling capture to pull out only the matching packets, then serves the resulting PCAP over HTTPS.

## What's new in v2

v1 was a pair of stdlib `http.server` scripts (`listener.py` / `fileserver.py`) reading a shared `config.json`, run directly on the host under systemd. v2 is a full rewrite, containerized and hardened for unattended operation:

- **FastAPI + gunicorn** instead of raw `http.server` — async request handling, typed config, a proper process supervisor.
- **Caddy at the edge** handles TLS, Basic auth, IP allowlisting, and serves extracted PCAPs directly — the app itself is unreachable except through Caddy (unix socket only, no published port).
- **Docker Compose** packaging — `docker compose up -d` replaces manual systemd unit installation.
- **Retention background task** — extracted PCAPs older than a configurable age (or past a total-size budget) are pruned automatically.
- **Concurrency gate + timeout hardening** — `npcapextract` runs are capped and bounded; a single misbehaving extraction can't pile up or hang the service.
- The legacy v1 scripts are preserved under [`old/`](old/) for reference; the wire-level webhook contract Sycope depends on is unchanged (see [SPEC.md](SPEC.md) §5).

## Requirements

### System

- **Linux** with a network interface for capture (default: `ens18`)
- **Docker** + **Docker Compose**
- **n2disk** — continuous packet recording to PCAP ([ntop.org](https://www.ntop.org/products/traffic-recording-replay/n2disk/)). Not yet containerized — runs on the host; see [`docs/reference/`](docs/reference/) for config templates.
- **npcapextract** — extracts packets from the recorded timeline (installed alongside n2disk)
- **Sycope** — configured to send webhook alerts to this service

### Storage

- `/storage/pcaps/rolling` — rolling PCAPs written by n2disk (mounted read-only into the API container)
- `/storage/pcaps/alerts` — extracted alert PCAPs (mounted read-write into the API container, read-only into Caddy)

## Project Structure

```
sycope_recorder/
├── src/sycope_recorder/
│   ├── main.py             # App entrypoint — builds Settings, wires up logging, exposes `app`
│   ├── api.py               # FastAPI routes: /extract, /healthz, /
│   ├── alert.py              # Parses the loose, legacy-compatible alert JSON
│   ├── bpf.py                 # Builds the BPF filter from a parsed alert + filter mode
│   ├── extraction.py           # Runs npcapextract as a subprocess, with timeout
│   ├── retention.py             # Background loop pruning old extracted PCAPs
│   ├── config.py                 # pydantic-settings: SR_-prefixed env config
│   └── logging_config.py          # Structured per-request logging
├── tests/                    # pytest unit + integration suite (stub npcapextract, no n2disk needed)
├── caddy/Caddyfile           # TLS, Basic auth, IP allowlist, static file serving, reverse proxy
├── compose.yaml              # Docker Compose stack (api + caddy; commented n2disk template)
├── compose.fieldtest.yaml    # Compose overrides for field testing
├── Dockerfile                # Multi-stage build (uv-based)
├── gunicorn.conf.py          # 1 worker, uvicorn worker class, unix socket
├── docs/
│   └── reference/            # n2disk.conf / n2disk.service templates (host install)
├── old/                      # Preserved v1 (config/, src/ flat scripts)
├── SPEC.md                   # Behavioral contract (request/response, legacy compatibility)
├── README_STACK.md           # What each piece of the stack is and why it was chosen
├── README_DEPLOY.md          # Deployment runbook
└── README_DIST.md            # Distribution/packaging notes
```

## Architecture

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
      │  parse alert → build BPF filter → run npcapextract (threadpool)
      ▼
   npcapextract (subprocess) → writes PCAP to the alerts volume
```

Caddy and the app never talk over TCP — they share a `run` volume containing a unix socket (`api.sock`). Caddy also mounts the `alerts` volume read-only so downloads never pass through Python. Full rationale for every choice above is in [README_STACK.md](README_STACK.md).

## Configuration

All app settings use the `SR_` env prefix (`pydantic-settings`, see `src/sycope_recorder/config.py`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SR_PUBLIC_HOST` | Public hostname (required, no default) | — |
| `SR_DOWNLOAD_PREFIX` | URL path prefix for downloads | `downloads` |
| `SR_TIMELINE_DIR` | Rolling PCAP directory (n2disk output) | `/storage/pcaps/rolling` |
| `SR_OUTPUT_DIR` | Extracted PCAP output directory | `/storage/pcaps/alerts` |
| `SR_DEFAULT_FILTER` | Default BPF filter mode | `full` |
| `SR_DEFAULT_BEFORE` | Default seconds before alert | `360` |
| `SR_DEFAULT_AFTER` | Default seconds after alert | `360` |
| `SR_MAX_CONCURRENT_EXTRACTIONS` | Max concurrent `npcapextract` runs | `1` |
| `SR_EXTRACT_TIMEOUT_SECONDS` | Timeout for a single extraction | `300` |
| `SR_RETENTION_MAX_AGE_DAYS` | Delete extracted PCAPs older than this | `7` |
| `SR_RETENTION_MAX_TOTAL_BYTES` | Total size budget for extracted PCAPs (`0` = unlimited) | `0` |
| `SR_RETENTION_INTERVAL_SECONDS` | How often the retention loop runs | `3600` |
| `SR_LOG_LEVEL` | Log level | `INFO` |
| `SR_LOG_FORMAT` | `text` or `json` | `text` |

Auth (`BASIC_AUTH_USER`/`BASIC_AUTH_HASH`) and the download IP allowlist (`ALLOWED_IPS`) are **Caddy-level**, not app settings — access control is enforced at the edge, before a request ever reaches Python. The `/extract` request body is capped at 2 MiB, enforced authoritatively by Caddy.

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

The API listens only on a unix socket; Caddy publishes 443 (and 80 → redirect) with a self-signed cert from its internal CA. Clients must trust Caddy's internal CA or skip verification. See [README_DEPLOY.md](README_DEPLOY.md) for the full runbook, including n2disk host setup.

## Sycope Webhook

Point Sycope's webhook action at:

```
POST https://<RECORDER_HOST>/extract?filter=full&before=360&after=360
```

with Basic-auth credentials matching `BASIC_AUTH_USER`/`BASIC_AUTH_HASH`. Filter modes and the `before`/`after` window are unchanged from v1:

| Mode | Includes |
|------|----------|
| `full` | client IP + server IP + port |
| `hosts` | client IP + server IP |
| `client` | client IP only |
| `server` | server IP only |
| `port` | server IP + port |

## Example Payload

```json
{
  "id": "alert_12345",
  "name": "Suspicious traffic",
  "clientIp": "10.0.0.10",
  "serverIp": "10.0.0.20",
  "serverPort": 443,
  "protocolName": "tcp",
  "unixTimestamp": 1739100000
}
```

## How It Works

```
Network traffic
     │
     ▼
  n2disk ──────► /storage/pcaps/rolling/ (rolling PCAPs)
                        │
Sycope alert            │
     │                  │
     ▼                  ▼
  FastAPI app ──► npcapextract ──► /storage/pcaps/alerts/*.pcap
                                        │
                                        ▼
                                    Caddy ──► HTTPS download
```

Every extraction outcome — a real download URL, `"NO BPF FILTER"`, or a timeout/failure string — is returned as HTTP 200 with the result duplicated in an `X-Result` header, matching the legacy Sycope webhook contract (Sycope parses body text, not status code).

## Development

```bash
uv sync
uv run pytest -q     # unit + integration; uses a stub npcapextract, no n2disk needed
uv run ruff check .
```

## Documentation

| Document | Covers |
|----------|--------|
| [SPEC.md](SPEC.md) | Full behavioral contract — request/response formats, legacy compatibility guarantees |
| [README_STACK.md](README_STACK.md) | What each component is, why it was chosen, how defaults were picked |
| [README_DEPLOY.md](README_DEPLOY.md) | Deployment runbook |
| [README_DIST.md](README_DIST.md) | Distribution/packaging notes |
| [docs/](docs/) | Design docs, n2disk config templates, passthrough notes |

## Troubleshooting

- **No extracted PCAPs created**: check that `npcapextract` is on `PATH` inside the container and `SR_TIMELINE_DIR` is correct.
- **Empty PCAP files**: BPF filter might be too strict, or the alert timestamp is outside the rolling window.
- **`"NO BPF FILTER"` response**: the alert payload is missing the IP/port/protocol fields needed to build a filter (see [`bpf.py`](src/sycope_recorder/bpf.py) for the exact rejection rule).
- **HTTP 429**: too many concurrent extractions — raise `SR_MAX_CONCURRENT_EXTRACTIONS` or retry after the `Retry-After` header.
- **HTTP 413 / connection reset on `/extract`**: request body over 2 MiB, rejected by Caddy before it reaches the app.
- **Permission errors**: confirm the `rolling` volume is readable and `alerts` is writable by the container; n2disk typically owns `rolling` as `n2disk:ntop`.
