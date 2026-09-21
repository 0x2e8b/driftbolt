# Sycope Traffic Recorder — Legacy System Specification

This document is a complete behavioral specification of the system in `old/`,
written to support a from-scratch, "drop-in compatible" reimplementation. It
describes *what the system does*, not just what the code looks like — including
defaults, edge cases, quirks, and a few internal inconsistencies discovered
while reading the code. Anyone building a replacement should be able to do so
from this document alone, without reading `old/` line by line.

A **"drop-in replacement"** means: existing Sycope webhook configuration,
existing `config/config.json` files, existing systemd units, and existing
n2disk/npcapextract installations should keep working unmodified against the
new implementation, unless a change is deliberately called out below.

---

## 1. Purpose

Continuously record raw network traffic to disk in rolling PCAP files. When
Sycope (a NetFlow/traffic-analysis platform) raises an alert, call a webhook
on this system with the alert's IP/port/protocol/time details. The system
builds a BPF (Berkeley Packet Filter) expression from those details, extracts
only the matching packets from a time window around the alert from the
rolling PCAP archive, and makes the extracted PCAP downloadable over HTTP.

This is fundamentally a **glue layer** between three things:
1. **n2disk** (ntop) — does the actual continuous packet capture to disk.
2. **npcapextract** (ntop, ships with n2disk) — does the actual time+BPF based
   extraction from the rolling capture ("timeline").
3. **Sycope** — the alerting system that triggers extraction via webhook.

The Python code itself does no packet processing — it parses an alert JSON
payload, builds a CLI invocation, shells out to `npcapextract`, and serves the
resulting file. This is important: **the "brains" of extraction are external
binaries**; the service is orchestration + a tiny inference layer for
mapping loose/varying alert JSON shapes into a BPF filter.

---

## 2. Architecture / Data Flow

```
Network traffic
     │
     ▼
  n2disk ──────► /storage/pcaps/rolling/  (rolling PCAPs, 5-min files, oldest overwritten)
                        │
Sycope alert (webhook)  │
     │                  │
     ▼                  ▼
 listener.py :8888 ──► npcapextract (subprocess) ──► /storage/pcaps/alerts/*.pcap
     │                                                     │
     │  (200 OK body = download URL, or error text)        ▼
     ▼                                              fileserver.py :8081 ──► HTTP GET download
  Sycope
```

Two independent long-running processes, no shared state beyond the
filesystem and `config/config.json`:

| Process | Default Port | Role |
|---|---|---|
| `listener.py` | 8888 | Webhook receiver + extraction trigger (writes files) |
| `fileserver.py` | 8081 | Static file server for extracted PCAPs (reads files) |

There is no message queue, no database, no shared process memory. All
coordination is via the filesystem (`output_dir`) and the `npcapextract`
subprocess's exit code / file presence.

---

## 3. External Dependencies (must shell out to / integrate with, not reimplement)

### 3.1 n2disk

- Third-party binary (`/usr/bin/n2disk`), not part of this codebase.
- Configured via `/etc/n2disk/n2disk.conf` (copied verbatim from
  `config/n2disk.conf`).
- Config used in this deployment (`config/n2disk.conf`):
  ```
  -i=ens18                       # capture interface
  -o=/storage/pcaps/rolling      # output dir
  --index                        # build extraction index
  --timeline-dir=/storage/pcaps/rolling
  --max-file-duration=300        # 5-minute rolling files
  -b=2048                        # buffer size (MB, ntop convention)
  -p=500                         # (n2disk flag, packet-related; not decoded further — treat as opaque passthrough)
  --disk-limit 80%               # rolling/overwrite threshold
  ```
- Run as a systemd service (`config/n2disk.service`): `Type=simple`,
  `Restart=always`, `RestartSec=5`, logs to journal.
- **The rolling directory is owned by `n2disk:ntop`.** The service user
  running the listener must be in the `ntop` group to read it (called out
  explicitly in troubleshooting — this is an operational gotcha, not
  something the Python code enforces).
- The new implementation does **not** need to reimplement n2disk config
  generation logic beyond shipping the same conf/unit templates — this is
  static config the operator installs once.

### 3.2 npcapextract

- Third-party CLI (installed alongside n2disk), invoked as a subprocess by
  the listener for every alert. This is the **core external contract that
  must be preserved exactly**:

  ```
  npcapextract -t <TIMELINE_DIR> -b "<BEGIN>" -e "<END>" -f "<BPF>" -o <OUTPUT_FILE>
  ```

  - `-t` — timeline directory (= `timeline_dir` config, the n2disk rolling
    output dir with its index).
  - `-b` / `-e` — begin/end timestamps, format `%Y-%m-%d %H:%M:%S`
    (local time, no timezone suffix), e.g. `2026-07-01 14:03:00`.
  - `-f` — a single BPF expression string (see §5.3 for construction rules).
  - `-o` — absolute output file path (must not exist as a directory; parent
    dir is created by the listener beforehand via `os.makedirs(..., exist_ok=True)`).
  - Must be resolvable on `PATH` for the listener's process user.
  - Invoked with `subprocess.run(cmd, capture_output=True, text=True, timeout=300)`
    — **300-second hard timeout**, no retry.
  - Success is judged by: return code `0` **AND** output file exists **AND**
    file size `> 0`. On success the listener returns the download URL.
  - A zero-byte output file (a "miss" — return code `0` but the filter
    matched nothing in the window) is logged as `MISS`, the empty file is
    deleted, and control **falls through to the shared failure path**: any
    stdout/stderr is logged and the listener returns
    `"ERROR: npcapextract failed"`. **This is a real quirk** (see §12.3): an
    empty match (which is not, strictly, a tool failure) is reported to the
    caller identically to a genuine `npcapextract` failure. Note this is
    *distinct* from the `"NO BPF FILTER"` case, which happens earlier and
    never runs the subprocess at all (§5.4 step 3).
  - Any non-zero exit **or** a missing output file → the same
    `"ERROR: npcapextract failed"` string, with stdout/stderr logged
    server-side only (never returned to the caller).
  - A timeout after 300s → the distinct string `"ERROR: npcapextract timeout"`.

### 3.3 Sycope

- External SIEM/NetFlow platform. Not part of this codebase. It is
  configured (by the Sycope operator, not by this system) with a webhook
  action pointing at `listener.py`. See §5 for the full webhook contract
  this system must continue to accept.

---

## 4. Storage Layout

| Path (default) | Purpose | Written by | Read by |
|---|---|---|---|
| `/storage/pcaps/rolling` | Continuous rolling capture + n2disk timeline index | n2disk | npcapextract (via listener) |
| `/storage/pcaps/alerts` | Extracted per-alert PCAPs | npcapextract (via listener) | fileserver |

Both paths are configurable (`timeline_dir`, `output_dir` in
`config.json`). `output_dir` is created on demand
(`os.makedirs(exist_ok=True)`) by the listener at startup and again before
every extraction; it is **not** created by the fileserver (fileserver only
warns if missing, does not create it — it does not need write access at
all, only read).

---

## 5. Component Spec: `listener.py` (webhook listener)

### 5.1 Startup behavior

- Loads config via shared config loader (§7).
- Creates `output_dir` if missing.
- Logs (but does not fail startup on) a missing `timeline_dir`.
- Binds `ThreadingHTTPServer` on `0.0.0.0:<listen_port>` (default `8888`).
  **Threaded** — each request handled in its own thread, so concurrent
  webhook deliveries are possible; concurrency of the expensive part
  (`npcapextract`) is separately bounded (§5.4).
- Logging: Python `logging`, level `INFO`, format
  `%(asctime)s [%(levelname)s] %(message)s`, to stdout (no file handler —
  systemd/journal captures it). HTTP access logging is suppressed
  (`log_message` overridden to no-op); all logging is application-level via
  the `log` logger.

### 5.2 `POST /extract` — the webhook endpoint

Actual path is not checked/routed on — **any POST is treated as the extract
action** (`do_POST` doesn't inspect `self.path` beyond parsing query
string). A real reimplementation may choose to route strictly on
`/extract`, but must not *require* Sycope to change its configured path,
and should keep accepting POSTs regardless of exact path to match legacy
leniency, or at minimum default the doc'd path.

**Query parameters** (all optional):

| Param | Type | Valid values | Default | Invalid-value behavior |
|---|---|---|---|---|
| `filter` | string | `full`, `hosts`, `client`, `server`, `port` | `default_filter` config (`full`) | empty string or unknown value → falls back to `default_filter`, with a warning logged |
| `before` | int (seconds) | any int | `default_before` config (`360`) | non-int → falls back to default; clamped to `[0, 86400]` |
| `after` | int (seconds) | any int | `default_after` config (`360`) | non-int → falls back to default; clamped to `[0, 86400]` |

> **Discrepancy found in legacy code**: the module docstring at the top of
> `listener.py` claims defaults of `before=30, after=60`, but the actual
> runtime defaults come from `config.json` and are `360`/`360` in the
> shipped config. **Do not trust the docstring's numbers** — trust
> `config.json` / the config table in §7. Preserve `config.json` as the
> source of truth in the reimplementation and drop the misleading numbers
> from any doc/help text you carry forward.

**Auth**: HTTP Basic auth, checked *before* body parsing. Only enforced if
both `listener_auth_user` and `listener_auth_pass` are non-empty (see §5.6).
On failure: `401`, header `WWW-Authenticate: Basic realm="pcap-extractor"`,
body `Unauthorized`.

**Body handling** (in order, each short-circuits with a specific status):

1. Missing `Content-Length` header → `411 Length Required`, body
   `Missing Content-Length`.
2. `Content-Length > 2 MiB (2 * 1024 * 1024 bytes)` → `413 Payload Too
   Large`, body `Payload too large`. **This is a hard cap — not
   configurable in the legacy system.**
3. Empty body after read → `400`, body `Empty request body`.
4. Body is not valid JSON → `400`, body `Invalid JSON` (JSON parse errors
   are logged server-side with body length and the parser's error message,
   but the raw body is not returned to the caller).
5. Any other exception during processing → `500`, body = `str(exception)`.
   (Leaks internal error text to the caller — a thing worth reconsidering,
   but note for compatibility that this is current behavior.)

**Concurrency gate**: a global `threading.Semaphore(max_concurrent_extractions)`
(default `1`) guards the actual `npcapextract` call — *not* the whole
request. If the semaphore can't be acquired non-blocking, respond
immediately: `429 Too Many Requests`, header `Retry-After: 5`, body `Too
many concurrent extractions`. The semaphore is released in a `finally`
regardless of extraction outcome.

**Success/response path** — on a request that passes all the above:

- Logs (INFO), for every request: a `"="*60` separator line, alert id/name,
  full list of top-level alert JSON keys (`Alert keys: [...]`), the
  effective URL params, the parsed local+UTC alert time, and the resolved
  flow tuple `client -> server:port (protocol)`. If either IP is missing,
  logs a warning (`BPF may be empty`) but still proceeds.
- Calls extraction (§5.4/§5.5).
- Response is **always HTTP 200** at this point (errors from extraction are
  reported as `200` with an error string body — only the earlier
  validation failures use non-200 codes). Response:
  - `Content-Type: text/plain`
  - `X-Result: <same string as body>` (or `EMPTY` if body were falsy,
    which shouldn't happen in practice since every code path returns a
    non-empty string)
  - Body = one of: a full download URL (`http://<host>:<fileserver_port>/<filename>`),
    `NO BPF FILTER`, `ERROR: npcapextract timeout`, or `ERROR: npcapextract failed`.

> **Important for a reimplementation**: callers (Sycope) apparently
> distinguish success/failure by **body content**, not HTTP status, since
> all outcomes after body-validation return `200`. A new implementation
> should preserve this (or, if changing it to use proper status codes,
> treat it as a deliberate breaking change to flag to the user/Sycope
> config, not an oversight).

### 5.3 Alert field parsing (`parse_alert`)

Sycope alert payloads are loosely/variably shaped. The parser tries several
field name aliases per logical field, in priority order, first match wins
per-field (not merged across fields):

| Logical field | Field name aliases tried (in order) | Extraction logic |
|---|---|---|
| Client IP | `clientIp`, `srcIp`, `src_ip`, `sourceIp`, `source` | string → used as-is; dict → `.addressString` key; anything else → skipped |
| Server IP | `serverIp`, `dstIp`, `dst_ip`, `destIp`, `destination` | same as above |
| Server port | `serverPort`, `dstPort`, `dst_port`, `destPort` | int and `>0` → used; numeric string → parsed to int; `0` or negative → treated as absent |
| Protocol | `protocolName`, `protocol`, `proto`, `ipProtocol` | int → mapped via `{1: icmp, 6: tcp, 17: udp}`; string → lowercased, kept only if one of `tcp`/`udp`/`icmp`, else discarded |
| Timestamp | `unixTimestamp`, `timestamp_unix`, `time` (numeric) | if value `> 1e12`, treated as **milliseconds** and divided by 1000, else treated as seconds |
| Timestamp (fallback) | `timestamp` (string) | parsed with format `%d.%m.%y %H:%M:%S` (2-digit year, day-first) |
| Timestamp (final fallback) | — | `datetime.now()` if nothing else matched |
| Alert ID | `id`, else `alertId`, else synthesized `alert_<unix_ts_int>` | used verbatim (later sanitized for filenames, see §5.4) |
| Alert name | `name`, else `alertName`, else `"Unknown"` | used only for logging, not filtering |

The `_find_field` helper checks field **presence** (`field in alert`) before
extraction, and only accepts a value if the extractor returns a truthy
result — so `serverPort: 0`, empty string IPs, etc. are treated as "field
not usable" and the next alias is tried; if no alias yields a value, the
logical field is `None`. This truthiness-based fallback applies to the four
flow fields (client IP, server IP, port, protocol) and to the timestamp.

> **Note — `id`/`name` differ**: unlike the flow fields, `id` and `name` are
> resolved with plain `dict.get` chaining
> (`alert.get("id", alert.get("alertId", f"alert_{int(unix_ts)}"))`), which
> keys off **absence only**, not truthiness. A present-but-`null` or empty
> `id` therefore is **not** replaced by the synthesized `alert_<ts>`
> fallback — it is used as-is (e.g. `id: null` → the string `"None"` after
> `str()` + sanitization in §5.4). A faithful reimplementation must
> replicate this presence-vs-truthiness asymmetry.

A reimplementation must replicate this alias table and fallback order
precisely, since real-world Sycope payloads vary and this is the system's
main compatibility surface with Sycope's alert schema (which may itself
vary by Sycope version/alert type).

### 5.4 Filename construction & extraction pipeline (`run_extraction`)

1. Compute `alert_time = datetime.fromtimestamp(parsed_timestamp)` (local
   time).
2. Compute window `[alert_time - before_seconds, alert_time + after_seconds]`,
   formatted `%Y-%m-%d %H:%M:%S` for the npcapextract CLI.
3. Build BPF filter (§5.5). If `None`/empty → return `"NO BPF FILTER"`
   immediately, **no subprocess is run**, no file created.
4. `os.makedirs(output_dir, exist_ok=True)`.
5. Sanitize alert id for filesystem use: keep only
   `[A-Za-z0-9\-_]` characters from `str(parsed["id"])`, truncate to 64
   chars; if the sanitized result is empty, use literal `"alert"`.
6. Filename: `{alert_time:%Y%m%d_%H%M%S}_{safe_id}.pcap`
   (e.g. `20260701_140300_alert_12345.pcap`). **This exact naming scheme is
   part of the URL contract returned to Sycope/the user and should be
   preserved** unless intentionally changed.
7. Output path: `os.path.join(output_dir, filename)` — flat directory, no
   subdirectories/date partitioning.
8. Run `npcapextract` per §3.2. On success: log `SUCCESS: <path> (<size> bytes)`
   and `URL: <fileserver_url>/<filename>`, and return that URL string
   (`f"{FILE_SERVER_URL}/{filename}"`, where `FILE_SERVER_URL =
   f"http://{config.host}:{config.fileserver_port}"` — **note: always
   `http://`, never `https://`**, and uses the **configured** `host`, not
   any request-derived host header — so `config.json`'s `host` value must
   be externally reachable/correct for the returned URL to work).

### 5.5 BPF filter construction (`build_bpf_filter`)

Filter modes (`FILTER_MODES` — a fixed lookup table, not user-extensible via
config):

| Mode | Client IP | Server IP | Port |
|---|---|---|---|
| `full` (default) | ✓ | ✓ | ✓ |
| `hosts` | ✓ | ✓ | ✗ |
| `client` | ✓ | ✗ | ✗ |
| `server` | ✗ | ✓ | ✗ |
| `port` | ✗ | ✓ | ✓ |

Construction algorithm, in order:
1. If protocol is known **and** it is not the case that
   `(protocol == "icmp" and server_port is present)`, prepend the bare
   protocol name (`tcp`/`udp`/`icmp`) as a BPF term.
   - Effectively: ICMP protocol term is **dropped** if a port also happens
     to be present (guards against a nonsensical `icmp and port N` filter
     from noisy alert data), but for tcp/udp the protocol term is always
     included when known, regardless of port.
2. If mode includes client and `client_ip` present → append `host <client_ip>`.
3. If mode includes server and `server_ip` present → append `host <server_ip>`.
4. If mode includes port and `server_port` present **and** protocol is
   `tcp`, `udp`, or unknown (`None`) — i.e. **not** `icmp` — append
   `port <server_port>`.
5. Join all terms with literal `" and "`.
6. **Rejection rule**: if there are zero terms, **or** exactly one term and
   that term is bare `tcp`/`udp`/`icmp` (a protocol-only filter with no
   host/port — considered too broad/useless), return `None` → triggers
   `"NO BPF FILTER"` upstream.

No IP validation is performed (any string reaching `host <str>` in the BPF
expression is trusted to be a valid IP/hostname — malformed input would
just produce an invalid BPF that npcapextract itself would presumably
reject, surfacing as `ERROR: npcapextract failed`). **A reimplementation may
choose to validate IPs earlier**, but should preserve the term-selection
logic above exactly, since it encodes real operational reasoning (e.g. the
ICMP/port interaction) that isn't obvious from first principles.

### 5.6 `GET` — health/help endpoint

- Also gated by the **same Basic auth** as `POST` (worth flagging: this
  means a load balancer/monitoring health check hitting `GET /` will get a
  `401` unless it also sends credentials — likely unintentional coupling,
  but it's current behavior).
- On success, returns `200`, `Content-Type: application/json` (with an
  explicit `Content-Length`), and a pretty-printed (`json.dumps(...,
  indent=2)`) JSON body with exactly these top-level keys:
  - `status` — the literal string `"ok"`.
  - `usage` — an object with `endpoint`
    (`"POST /extract?filter=MODE&before=SEC&after=SEC"`), `filter_modes`
    (the 5 mode names → human descriptions), and `defaults`
    (`filter`/`before`/`after`, from config).
  - `examples` — three example URLs using the literal placeholder `HOST`
    and the real configured `PORT` (the example URLs' `before`/`after`
    values are illustrative literals — `30`/`60` etc. — **not** the
    configured defaults).
- Because the body contains `"status": "ok"`, it *can* double as a crude
  liveness signal — but only for a caller that already holds the listener's
  Basic-auth credentials (see §12.4), so it is not usable as an
  unauthenticated probe. It is primarily documentation-in-JSON, not a
  dedicated health contract. A reimplementation is free to add a real
  unauthenticated `/healthz` in addition (§14), but should keep this JSON
  response on plain (authenticated) `GET` for compatibility with anyone
  currently curling it. **A drop-in reimplementation must preserve the
  `"status": "ok"` field and the `usage`/`examples` structure.**

---

## 6. Component Spec: `fileserver.py`

- Serves `output_dir` (config key, same directory the listener writes into)
  as static files via `http.server.SimpleHTTPRequestHandler`, subclassed.
- `ThreadingHTTPServer` on `0.0.0.0:<fileserver_port>` (default `8081`).
- **Auth**: independent Basic-auth credential pair
  (`fileserver_auth_user`/`fileserver_auth_pass`), same disabled-if-empty
  semantics as the listener, same realm-style challenge (realm
  `"pcap-files"`), checked on both `GET` and `HEAD`.
- **IP allowlist** (`allowed_ips`, list of CIDR strings or bare IPs; empty =
  allow all): checked *after* auth passes. Uses `ipaddress.ip_network(...,
  strict=False)` per entry; invalid entries are logged to stdout and
  skipped (not fatal). Client IP is taken from `self.client_address[0]`
  (i.e. TCP peer address — **no `X-Forwarded-For` handling**, so if this is
  ever put behind a reverse proxy, the allowlist would see the proxy's IP,
  not the real client's, unless the reimplementation adds proxy-awareness).
  Rejection → `403 Forbidden`, plain text body `Forbidden`.
- **Directory listing is always disabled**: `list_directory` is overridden
  to unconditionally return `403` with body `Directory listing disabled`,
  regardless of whether an `index.html`-style default would otherwise be
  served. Effectively only exact, known filenames are servable.
- Startup: prints (not logged via `logging`, just `print`) directory
  existence warning, bind address/port, whether auth is enabled, and the
  resolved allowlist. **This uses `print`, unlike the listener's structured
  logging** — an inconsistency worth normalizing in the rewrite but not a
  functional requirement.
- No write, delete, or listing API — purely a read-only static file GET/HEAD
  server for whatever the listener has already written.

---

## 7. Component Spec: `config_loader.py` (shared)

Used by both `listener.py` and `fileserver.py`. Must be preserved as a
single shared config contract even if reimplemented in another language —
i.e. **one config file format, one loading path, shared by both services**.

- **Location**: always `<project_root>/config/config.json`, resolved as
  `dirname(dirname(abspath(__file__)))/config/config.json` — i.e. hardcoded
  relative to the source file's location, not `argv`, not `cwd`, not an env
  var. **This means the "project root / src layout" relationship is load-bearing**
  for legacy deployments; a reimplementation can change this but should
  provide an equally simple, documented resolution rule (e.g. an env var
  override with the same default relative path, for true drop-in behavior).
- **Missing file** → prints `ERROR: Config file not found: <path>` to
  stderr, `sys.exit(1)`. No default config is synthesized.
- **Required keys** (hard failure if any missing — same stderr+exit(1)
  pattern): `host`, `listen_port`, `fileserver_port`, `timeline_dir`,
  `output_dir`, `default_filter`, `default_before`, `default_after`.
- **Optional keys with defaults applied in-process** (not written back to
  the file): `listener_auth_user`, `listener_auth_pass`,
  `fileserver_auth_user`, `fileserver_auth_pass` → default `""`;
  `allowed_ips` → default `[]`.
- **Backward-compatibility shim**: if a config still uses **old unified**
  keys `basic_auth_user` / `basic_auth_pass` (pre-dating the
  listener/fileserver credential split), those values are copied into
  `listener_auth_user`/`pass` and `fileserver_auth_user`/`pass` **only if
  the new-style keys aren't already present**. This means old configs from
  before the split continue to work with a single shared credential pair
  applied to both services. **A reimplementation should keep accepting this
  legacy key pair** if any currently-deployed config might still use it, or
  explicitly document it as dropped.
- **No config reload / hot-reload**: config is read once, at process start,
  in module scope of each script (`_config = load_config()` runs at import
  time). Changing `config.json` requires restarting both services (systemd
  restart) to take effect. Not a bug, just a constraint to intentionally
  keep, relax, or improve.
- **`check_basic_auth(headers, user, pwd)`**: shared by both services.
  - If **both** `user` and `pwd` are empty → auth is **disabled**, always
    returns `True` (note: it's "both empty", not "either empty" — a config
    with a username set but empty password would still enforce auth and
    presumably always fail unless the client also sends an empty password).
  - Otherwise requires `Authorization: Basic <base64(user:pass)>`; decode
    failures → `False`; comparison uses `hmac.compare_digest` (constant-time)
    against **both** username and password — a deliberate timing-attack
    mitigation to preserve.

---

## 8. Full Configuration Reference (`config/config.json`)

| Key | Type | Default (shipped) | Required | Notes |
|---|---|---|---|---|
| `host` | string (IP/hostname) | `192.168.0.109` | yes | Used to build the *returned* file-download URL — must be externally reachable by whoever fetches the PCAP (Sycope/analyst), not just bindable locally. |
| `listen_port` | int | `8888` | yes | Listener bind port (binds `0.0.0.0`). |
| `fileserver_port` | int | `8081` | yes | Fileserver bind port (binds `0.0.0.0`). |
| `timeline_dir` | string (path) | `/storage/pcaps/rolling` | yes | Passed straight to `npcapextract -t`; must be n2disk's `--timeline-dir` output with its index. |
| `output_dir` | string (path) | `/storage/pcaps/alerts` | yes | Extraction output; also what the fileserver serves. |
| `default_filter` | string | `full` | yes | Must be one of the 5 fixed mode names; no validation prevents setting a bogus default in config (falls through to being treated as unknown mode → mode lookup itself defaults to `full` internally at use-time — double safety net). |
| `default_before` | int (sec) | `360` | yes | Also the fallback when the `before` query param is missing/invalid. |
| `default_after` | int (sec) | `360` | yes | Same, for `after`. |
| `max_concurrent_extractions` | int | `1` | no (defaults to `1` if unparsable, min-clamped to `1`) | Global concurrency ceiling on simultaneous `npcapextract` subprocesses. |
| `listener_auth_user` | string | `""` | no | Empty (with pass also empty) disables auth. |
| `listener_auth_pass` | string | `""` | no | — |
| `fileserver_auth_user` | string | `""` | no | Independent from listener's. |
| `fileserver_auth_pass` | string | `""` | no | — |
| `allowed_ips` | array of string | `[]` | no | CIDR or bare IP; empty = allow all; fileserver-only (listener has no IP allowlist). |

Legacy/deprecated (still accepted via shim, see §7): `basic_auth_user`,
`basic_auth_pass`.

---

## 9. Deployment / Systemd Contract

Three services conventionally deployed:

| Unit | Purpose | Ships as template in this repo? |
|---|---|---|
| `n2disk.service` | Continuous capture (3rd party binary) | Yes, in `config/n2disk.service` → installed to `/etc/systemd/system/n2disk.service`, config to `/etc/n2disk/n2disk.conf` |
| `pcap-listener.service` | Runs `listener.py` | No — only documented inline in README as a heredoc; not shipped as a file in `config/` |
| `pcap-fileserver.service` | Runs `fileserver.py` | No — same, README heredoc only |

Both app-level units follow the same pattern: `Type=simple`,
`WorkingDirectory=/opt/sycope_recorder/src`, `ExecStart=/usr/bin/python3
/opt/sycope_recorder/src/<script>.py`, `Restart=always`, `RestartSec=5`,
`WantedBy=multi-user.target`. This implies a canonical install path of
`/opt/sycope_recorder/` with `src/` and `config/` subdirectories — matching
the config-loader's relative-path resolution in §7. **If the reimplementation
changes the install layout, the config-file resolution rule and these unit
templates must change together.**

Operational note carried from README troubleshooting: the process user
running these units needs group membership in `ntop` to read the
n2disk-owned `timeline_dir`.

There is **no containerization, no package (no `setup.py`/`pyproject.toml`/
`requirements.txt`)** in the legacy system for the two core services — they
run directly against system **Python 3.7+** using only the standard library
(`http.server`, `json`, `subprocess`, `threading`, `ipaddress`, `hmac`,
`base64`, `logging`, `functools`). Note: the README badge and its
"Requirements" section claim **Python 3.6+**, but this is **incorrect** —
both services use `http.server.ThreadingHTTPServer` (added in 3.7) and the
fileserver uses `SimpleHTTPRequestHandler(directory=...)` (the `directory`
parameter was also added in 3.7), so the real floor is **3.7** (see §12.13).
A reimplementation should target a currently-supported runtime regardless
and correct the stated minimum. Only the optional demo script (`netflow_replay.py`)
has an external dependency (`dpkt`), which is **not** installed/declared
anywhere (no requirements file at all in the repo) — anyone running that
script must `pip install dpkt` manually. This is worth fixing (e.g. a
`requirements-demo.txt` or moving the demo out of the core dependency
surface) but is not part of the core service's dependency footprint.

---

## 10. Component Spec: `netflow_replay.py` (demo/optional — not part of core system)

Not involved in the alert→extract→serve pipeline. A standalone demo/test
data generator: reads a static PCAP of NetFlow v9 packets, rewrites the
NetFlow v9 header's Unix-timestamp field (bytes 8–11, big-endian `!I`) to
"now" for each packet as it replays, and sends the UDP payloads to a
configured Sycope collector IP:port, spread evenly across the first 55
minutes of every hour (loops forever, waiting for the top of each hour
between bursts). Configuration is **hardcoded module-level constants**
(`PCAP_FILE`, `SYCOPE_IP`, `SYCOPE_PORT`, `REPLAY_DURATION`), not read from
`config.json` — intentionally separate from the main config system since
it's a demo tool, not a deployed service. Requires `dpkt` (not required by
the rest of the system). **Optional to port** — useful for
integration-testing a new implementation's ability to receive Sycope-style
alerts end-to-end, but not part of the production contract.

---

## 11. Security Model (as-is — a description of current posture, not a recommendation)

- Both HTTP services default to **fully open, unauthenticated**
  (`listener_auth_user`/`pass` and `fileserver_auth_user`/`pass` all empty
  by default in shipped config). README explicitly warns operators to put
  them behind a firewall/reverse proxy/VPN if exposed.
- No TLS anywhere — plain HTTP, plaintext Basic-auth credentials on the
  wire if enabled. Assumed trusted-network deployment.
- Auth is per-service, independently configurable (listener vs fileserver
  have separate credential pairs) — Sycope's webhook config needs the
  listener's credentials; anyone downloading extracted PCAPs needs the
  fileserver's.
- Fileserver additionally supports IP allowlisting (CIDR-based); listener
  does not have an equivalent allowlist option.
- `hmac.compare_digest` used for credential comparison (timing-safe) — a
  detail worth preserving even though the overall model (plaintext HTTP
  Basic) is weak.
- Request body size is capped at 2 MiB on the listener (hardcoded, not
  configurable) as a crude DoS guard.
- `npcapextract` concurrency is capped (configurable, default 1) as the
  main resource-exhaustion guard against alert floods; excess requests get
  `429`+`Retry-After: 5` rather than queuing.
- The `500` error handler on the listener returns the raw Python exception
  string in the HTTP body — an information-disclosure smell worth deciding
  whether to preserve or tighten in the rewrite.

---

## 12. Known Quirks / Inconsistencies Found During Review

Flagging these explicitly so the modernization can make a **deliberate**
choice (preserve for compatibility vs. fix) rather than accidentally
reproducing or accidentally breaking them:

1. **Docstring/config default mismatch**: `listener.py`'s module docstring
   says `before` defaults to 30s and `after` to 60s; the actual shipped
   config default is 360/360. Trust config, fix the docs in the rewrite.
2. **All extraction outcomes return HTTP 200**, differentiated only by
   response *body text* (`NO BPF FILTER`, `ERROR: ...`, or a URL) and an
   `X-Result` header duplicating the body. Only pre-extraction validation
   failures (auth, malformed request) use real status codes. Sycope's
   webhook consumer presumably parses body text, not status — verify before
   changing this in a rewrite, since it could silently break Sycope-side
   alert handling.
3. **A zero-byte extraction result (BPF matched nothing in the time
   window)** is logged as `MISS`, the empty file is deleted, but the
   caller-facing response is indistinguishable from a genuine
   `npcapextract` failure (`"ERROR: npcapextract failed"`). There is no way
   for a caller to tell "no matching packets" apart from "the tool broke."
4. **`GET` health/help endpoint is behind the same Basic auth** as the
   extraction endpoint — likely unintentional for anything hoping to use it
   as an unauthenticated liveness probe.
5. **Fileserver uses `print()` for its own startup diagnostics** while the
   listener uses the `logging` module — inconsistent operational tooling
   (matters for log aggregation, not behavior).
6. **No `X-Forwarded-For`/proxy support** in the fileserver's IP allowlist
   — if ever placed behind a reverse proxy, the allowlist becomes
   effectively useless (always sees the proxy IP) unless explicitly
   updated.
7. **Config is read once at import time**; there is no SIGHUP/reload
   mechanism — every config change requires a service restart.
8. **No IP allowlist on the listener** (only on the fileserver) — anyone
   who can reach port 8888 can trigger extractions (rate-limited only by
   the concurrency semaphore, not by source), unless upstream firewalling
   handles this.
9. **`allowed_ips` invalid entries are silently logged and skipped** at
   startup (fileserver) rather than causing a hard config-validation
   failure — a typo'd CIDR silently narrows/loosens the allowlist without
   obviously failing startup.
10. **No automated tests, no CI, no linting config** anywhere in the
    repository.
11. **`netflow_replay.py`'s dependency (`dpkt`) is undeclared** anywhere
    (no requirements file in the whole repo).
12. **Filenames are only alert-id + timestamp based, flat directory** — at
    scale, `output_dir` accumulates one file per alert forever; there's no
    retention/cleanup policy anywhere in the codebase (README doesn't
    mention one either) — operators are presumably expected to manage
    retention of `/storage/pcaps/alerts` themselves (e.g. via external
    cron/logrotate-style tooling), unlike the rolling capture dir which
    n2disk manages itself via `--disk-limit`.
13. **README understates the Python floor**: the badge and Requirements
    section say `Python 3.6+`, but the code uses `ThreadingHTTPServer` and
    `SimpleHTTPRequestHandler(directory=...)`, both of which are **3.7+**
    features. On 3.6 the services fail to import/start. The real minimum is
    **3.7** (§9). Additionally, `datetime.utcfromtimestamp` (used only in a
    log line, listener.py) is deprecated as of Python 3.12 — harmless today,
    but a rewrite should use a timezone-aware equivalent.
14. **Non-numeric `Content-Length` is unhandled**: `content_length =
    int(self.headers.get("Content-Length", 0))` runs **outside** the
    `try/except` that produces the `400`/`500` responses. A present-but-
    non-numeric `Content-Length` (e.g. `abc`) raises `ValueError` that
    escapes `do_POST`, so the client gets a dropped/failed connection rather
    than a clean `4xx`. A reimplementation should validate this header and
    return `400`.
15. **Fileserver does *not* suppress HTTP access logging**: only the
    listener overrides `log_message` to a no-op (§5.1). The fileserver's
    `SimpleHTTPRequestHandler` keeps the default per-request access log to
    **stderr**, so — combined with its `print()`-based startup diagnostics
    (§6, §12.5) — the fileserver has two ad-hoc output streams and no use of
    the `logging` module at all. Worth normalizing in the rewrite.

---

## 13. Compatibility Checklist for a Drop-In Reimplementation

If the goal is Sycope/operator-transparent replacement (no changes needed
on the Sycope side, in existing `config.json` files, or in existing
systemd/n2disk setups), the new implementation must preserve, exactly:

- [ ] Accepts `POST` (any path, or at least `/extract`) with query params
      `filter`, `before`, `after`, same names/semantics/defaults/clamping
      (`[0, 86400]`) and same 5 filter-mode names and their host/port
      inclusion rules (§5.5 table).
- [ ] Same JSON alert body parsing — same field alias lists and priority
      order for client IP, server IP, port, protocol, timestamp, id, name
      (§5.3 table).
- [ ] Same BPF construction algorithm, including the ICMP+port suppression
      rule and the "reject if only a bare protocol term" rule (§5.5).
- [ ] Same `npcapextract` invocation shape (`-t -b -e -f -o`, timestamp
      format `%Y-%m-%d %H:%M:%S`), same 300s timeout, same
      success/miss/failure classification (§3.2, §5.4).
- [ ] Same output filename pattern:
      `{alert_time:%Y%m%d_%H%M%S}_{sanitized_id}.pcap`, same id sanitization
      rule (alnum + `-`/`_`, 64-char cap, `"alert"` fallback).
- [ ] Same returned URL shape: `http://{config.host}:{fileserver_port}/{filename}`.
- [ ] Same response body value set on `POST`: a URL string, `NO BPF
      FILTER`, `ERROR: npcapextract timeout`, or `ERROR: npcapextract failed`
      — and the same all-200-status behavior, *unless* explicitly
      renegotiating the Sycope-side integration.
- [ ] Same request-validation status codes: `411` (no Content-Length),
      `413` (>2MiB), `400` (empty body / invalid JSON), `401` (bad/missing
      Basic auth), `429` + `Retry-After: 5` (concurrency exceeded).
- [ ] Same `config/config.json` key names, types, and defaults (§8),
      including the legacy `basic_auth_user`/`basic_auth_pass` shim if any
      live deployments might still rely on it.
- [ ] Same config file resolution convention (or a documented, equally
      simple replacement) relative to install layout.
- [ ] Fileserver: same static-GET-only semantics, directory listing always
      403, same independent auth pair, same CIDR-based `allowed_ips`
      (client IP = raw TCP peer, no proxy header support unless
      deliberately added), same 403 body text.
- [ ] Same systemd unit shape/paths for `n2disk.service` (verbatim — it's a
      3rd-party binary's config, do not touch), and equivalent
      `pcap-listener`/`pcap-fileserver` unit conventions if systemd remains
      the deployment model.
- [ ] Preserve (or deliberately supersede with a migration note) all items
      in §12 — each is a real behavioral trait some downstream automation
      may already depend on.

---

## 14. Suggested Focus Areas for the Rewrite (non-binding — implementation choices, not spec)

These are opportunities, not requirements — call out anywhere the new
project intentionally diverges from legacy behavior so it's a documented
decision rather than a silent regression:

- Add structured status codes for extraction outcomes while keeping a
  legacy-compatible response mode (e.g. a config flag or API version) if
  Sycope's webhook parsing can't be changed immediately.
- Add an unauthenticated `/healthz` distinct from the documented/auth'd
  help endpoint.
- Add retention/cleanup for `output_dir` (age- or size-based) since nothing
  currently manages it.
- Add an IP allowlist to the listener, mirroring the fileserver's.
- Consider `X-Forwarded-For`-aware IP allowlisting if a reverse proxy is
  ever introduced.
- Consider disambiguating "BPF matched zero packets" from "tool execution
  failed" in the response contract.
- Pin/declare dependencies properly (even though core services are
  currently stdlib-only) and add a test suite (there is currently none).
- Config hot-reload or at least a documented `SIGHUP`/reload story.
