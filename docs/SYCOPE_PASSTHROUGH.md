# Sycope Passthrough integration

How the recorder is exposed to Sycope operators through Sycope's own
**Passthrough** integration, instead of exposing the recorder's Caddy
endpoint directly. This document describes the Sycope-side configuration;
for the recorder's own stack see `README_STACK.md`.

## What Passthrough is

Passthrough (`Settings → Integrations → Passthrough`) is a reverse-proxy
gateway built into Sycope. A user or webhook calls a Sycope-hosted URL —
`https://<sycope-host>/npm/api/v1/passthrough/<name>/<path>` — and Sycope
forwards the request to a configured backend URL, injecting its own
authentication (Basic/Bearer) to that backend. The caller only ever
authenticates against Sycope; the backend's own credentials never reach
the browser or the alert engine.

This is distinct from **External Destinations** (`Integrations → External
Destinations`), which is Sycope calling *out* to a fixed URL as an alert
action. The two compose: an External Destination action can target a
Passthrough URL instead of the backend directly, so the same
Sycope-mediated auth and audit trail apply to alert-triggered calls, not
just to interactive ones.

## Why we use it for the recorder

The recorder's Caddy edge (`https://172.16.60.161:8443`) uses HTTP Basic
Auth and a self-signed certificate (`tls internal`) — see
`README_STACK.md`. Routing all traffic through Sycope's Passthrough
instead of exposing that endpoint directly gives us:

- **No shared secret in the browser.** Operators authenticate with their
  Sycope session; Sycope injects the recorder's Basic Auth server-side.
- **Role-based access instead of IP allowlisting.** Access Rules gate by
  Sycope role per path/method, which is more meaningful than the
  `ALLOWED_IPS` CIDR ranges in the recorder's `.env` (which are broad
  RFC1918 ranges in practice and don't distinguish users).
- **A central audit trail** (`Audit Calls`, see below) instead of no
  logging at all — the recorder itself doesn't log who downloaded what.
- **No user-facing TLS trust prompt.** The recorder's self-signed cert
  only has to be trusted by Sycope's backend (`SSL Verify` off), not by
  every operator's browser.

## Configuration on 172.16.60.160

Passthrough name: `recorder`.

| Field | Value |
|---|---|
| URL | `https://172.16.60.161:8443` |
| Authentication | Basic, user `sycope`, password matching the recorder's `BASIC_AUTH_HASH` |
| SSL Verify | **off** — the recorder's Caddy uses `tls internal` (self-signed); see caveat below |
| Access Rules | see table below |
| Audit Calls | on |

### Access Rules

| Path (regex) | Method | Roles |
|---|---|---|
| `^/downloads/.*` | GET | `ROLE_ADMIN`, `ROLE_USER`, + two custom roles |
| `^/.*` | POST | `ROLE_ADMIN`, `ROLE_USER`, + two custom roles |

Two rules because the recorder serves two different kinds of traffic
through the same backend: GET for PCAP downloads, POST for the alert
webhook (`/extract`). A request that matches no rule is denied by
default — there is no rule needed for paths that should be blocked.

**Known pitfall:** a trailing space in the Path regex (`^/.* ` instead of
`^/.*`) silently makes the rule match nothing — no request will ever
satisfy it, and Sycope returns a plain 401 with no indication the regex
itself is the problem. Always verify the exact string via
`GET /npm/api/v1/config/passthrough` (authenticated) after saving, not
just by re-opening the form.

### SSL Verify caveat

`SSL Verify: off` means Sycope does not validate the recorder's
certificate — acceptable for this internal-network deployment, but it is
a deliberate weakening of transport security, not a default to leave in
place unexamined. The correct long-term fix is a certificate the Sycope
host actually trusts (an internal CA imported into
`Settings → Security → Certificates`, or a properly issued cert on the
recorder's Caddy), at which point `SSL Verify` can be turned back on.

## How to use it

### Downloading a PCAP (GET)

Operators use:

```
https://172.16.60.160/npm/api/v1/passthrough/recorder/downloads/<filename>
```

If already logged into Sycope, the file downloads immediately — no
separate login prompt, no certificate warning. The recorder itself
returns this URL directly in its webhook response (see "Recorder-side
change" below), so operators clicking a link in Sycope never need to
construct it by hand.

### Triggering extraction from an alert (POST)

The alert's External Destination (REST client) action must point at
Sycope, not at the recorder directly:

| Field | Value |
|---|---|
| Host | `172.16.60.160` |
| Port | `443` |
| Path | `/npm/api/v1/passthrough/recorder/extract` |
| Query params | unchanged (`filter`, `before`, `after`) |
| Authentication | Basic Auth **to Sycope** (a service account with a role from the Access Rules table), not to the recorder |

Calling `/npm/api/v1/passthrough/...` without any Sycope-side
authentication returns 401 — Passthrough enforces auth on every call,
including calls originating from the alert engine itself. There is no
"trusted internal" bypass, so the External Destination action needs
real Sycope credentials, exactly as an interactive user would.

### Recorder-side change: returning a Passthrough URL

By default the recorder builds its download URL from `SR_PUBLIC_HOST`
(`https://172.16.60.161:8443/downloads/<file>`) — the same variable
Caddy uses for TLS SNI, so it can't simply be repointed at Sycope without
breaking Caddy's own routing.

The recorder supports an optional override, `SR_DOWNLOAD_URL_BASE`
(`download_url_base` in `Settings`), which replaces only the host part of
the returned URL, leaving `SR_PUBLIC_HOST`/Caddy untouched:

```
SR_DOWNLOAD_URL_BASE=172.16.60.160/npm/api/v1/passthrough/recorder
```

With this set, `run_extraction()` returns
`https://172.16.60.160/npm/api/v1/passthrough/recorder/downloads/<file>`
instead of the direct recorder URL. Unset, behavior is unchanged
(backward compatible with deployments that don't use Passthrough).

## Verifying the setup

```bash
# 1. Log in to Sycope, keep the session cookie
curl -sk -c cookies.txt -X POST https://172.16.60.160/npm/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'

# 2. Confirm the passthrough config is what you expect
curl -sk -b cookies.txt https://172.16.60.160/npm/api/v1/config/passthrough | python3 -m json.tool

# 3. Simulate the alert webhook through Passthrough
curl -sk -b cookies.txt -X POST \
  'https://172.16.60.160/npm/api/v1/passthrough/recorder/extract?filter=full&before=30&after=30' \
  -H 'Content-Type: application/json' \
  -d '{"clientIp":"10.0.0.5","serverIp":"10.0.0.6","port":443,"protocol":"TCP"}'
# → expect a Passthrough-prefixed download URL, HTTP 200

# 4. Download the file through the returned URL
curl -sk -b cookies.txt -o test.pcap 'https://172.16.60.160/npm/api/v1/passthrough/recorder/downloads/<filename>'
file test.pcap   # expect: pcap capture file...
```

A 401 at step 3 with no session cookie confirms Access Rules are being
enforced (expected); a 502 at step 3/4 usually means Sycope couldn't
reach the recorder — check `SSL Verify` first before assuming a
network/firewall problem, since a TLS handshake failure against a
self-signed cert also surfaces as 502 with no corresponding entry in the
recorder's Caddy logs.

## restAudit: querying the call trail

With `Audit Calls` enabled, every Passthrough-mediated request — GET
downloads and POST extractions alike — is written to a Sycope index
called **restAudit**, browsable like any other Sycope data stream
(`Stats` view, stream selector `restAudit`).

Relevant fields:

| Field | Meaning |
|---|---|
| Time | When the call was made |
| Action Name | The Passthrough name (`recorder`) |
| Response ID | Correlates to the entry surfaced in the `alerts` stream (see below) |
| Response Data | The response body — for a successful extraction, this is the download URL itself |
| HTTP Code | Status returned by the backend (via Sycope) |
| Source Stream Name | Which Sycope stream triggered the call (`alerts` for alert-driven extractions, `manual` for interactive use) |
| Username | The Sycope user or service account that made the call |

### Correlation with alerts

For POST calls made by an alert's External Destination action, the
`restAudit` entry's response is also surfaced back on the triggering
alert itself, in the **REST API Response** column of the `alerts`
stream — this is where the download URL an alert produced actually ends
up visible to an analyst working the alert, without having to
cross-reference `restAudit` manually. In practice:

- `alerts` stream → `REST API Response` column → the download URL for
  that specific alert.
- `restAudit` stream → full call log, useful for auditing *who* pulled a
  given PCAP (or the raw extraction call) after the fact, independent of
  which alert triggered it.

### Practical use

- Filtering `restAudit` by `Username` shows every recorder interaction
  by a given account — useful when auditing who accessed traffic
  captures, since the recorder itself keeps no such log.
- Filtering by `HTTP Code != 200` surfaces failed extractions (backend
  down, `npcapextract` failure, TLS misconfiguration) without needing
  shell access to the recorder's container logs.
- `Response Data` for a GET download call will show the request was
  served, but — unlike the POST case — does not itself contain the PCAP
  content; it's a metadata/audit record, not a copy of the file.
