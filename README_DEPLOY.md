# Deploying a Dist to a Target Host

This is the step-by-step runbook for taking a dist produced per
`README_DIST.md` (a pre-built `sycope-recorder-api` image, `caddy:2`,
`compose.yaml`, `caddy/Caddyfile`, and a `compose.dist.yaml` override) and
standing it up on a target host. Follow the steps in order — later steps
assume earlier ones are done.

## 1. Check host prerequisites

- [ ] Linux host with Docker Engine + the Compose plugin installed
      (`docker compose version` succeeds).
- [ ] Enough disk under wherever `/storage/pcaps/rolling` and
      `/storage/pcaps/alerts` will live — rolling capture size is driven by
      n2disk's `--disk-limit` (`docs/reference/n2disk.conf`), alerts grow
      until the app's own retention sweep trims them (`SR_RETENTION_*`,
      step 6).
- [ ] Inbound firewall allows `443` (and `80` if you want the HTTP→HTTPS
      redirect) from wherever Sycope and download clients connect from.
- [ ] Outbound: only needed if pulling images from a registry (dist option
      2A in `README_DIST.md`); not needed for the offline tarball path.

## 2. Check the recorder/capture side is ready

The `api` container only *reads* from the rolling capture — it does not
record traffic itself. Before deploying `api`, confirm:

- [ ] n2disk (or the containerized `recorder`, if you've integrated it per
      `README_DIST.md`'s recorder section) is already running and writing
      rolling PCAPs + a timeline index to a known path on this host.
- [ ] That path is what you'll bind-mount as `rolling` in step 5 — note it
      down now.
- [ ] The user the `api` container will read as can access that path.
      Legacy convention is the directory being owned `n2disk:ntop`
      (`SPEC.md` §3.1/§9) — you'll need matching group access or permissive
      mode bits on the bind mount, or extractions will silently fail to
      find data.

If the recorder isn't wired up yet, stop here and finish that first — do
not deploy `api` against an empty/missing rolling path, since every
`/extract` call will just report `NO BPF FILTER`-adjacent failures with no
data to extract from.

## 3. Get the dist artifacts onto the host

Depending on which distribution method was used (see `README_DIST.md`):

- **Registry:** `docker login <registry>` then
  `docker compose -f compose.yaml -f compose.dist.yaml pull`.
- **Offline tarballs:** copy `sycope-recorder-api.tar`, `caddy.tar`,
  `compose.yaml`, `caddy/Caddyfile`, and `compose.dist.yaml` to a
  deployment directory (e.g. `/opt/sycope-recorder/`), then:
  ```bash
  docker load -i sycope-recorder-api.tar
  docker load -i caddy.tar
  ```
- [ ] Verify both images are present: `docker images | grep -E 'sycope-recorder-api|caddy'`.
- [ ] Verify `compose.dist.yaml`'s `image:` tag matches what you just
      loaded/pulled — a mismatch here is the most common "why won't it
      start" mistake.

## 4. Lay out the deployment directory

On the target host, under your chosen deployment directory you should now
have exactly:

```
compose.yaml
compose.dist.yaml
caddy/Caddyfile
```

Do not copy source, tests, or docs — the dist intentionally excludes them.

## 5. Wire the `rolling` volume to the real capture path

`compose.yaml` defines `rolling` as a Docker-managed named volume by
default. Point it at the actual path from step 2 with a bind mount, added
to `compose.dist.yaml` alongside the `image:` override:

```yaml
volumes:
  rolling:
    driver: local
    driver_opts:
      type: none
      device: /storage/pcaps/rolling   # <- the real path from step 2
      o: bind
```

- [ ] Confirm the path exists and is non-empty (n2disk has written at
      least one rolling file) before moving on.

## 6. Configure environment

Create a `.env` file next to `compose.yaml` (docker compose loads it
automatically). Required and commonly-set variables:

| Variable | Required | Notes |
|---|---|---|
| `SR_PUBLIC_HOST` | **yes** | Hostname Sycope/clients will hit; used in the returned download URL and Caddy's TLS SNI. |
| `BASIC_AUTH_USER` | **yes** | Shared Basic-auth username, enforced by Caddy. |
| `BASIC_AUTH_HASH` | **yes** | Bcrypt hash — generate in step 7, not a plaintext password. |
| `ALLOWED_IPS` | no | CIDR allowlist for downloads (and `/extract` if you add it to the Caddyfile's `handle` block); defaults to open (`0.0.0.0/0 ::/0`) — set this in anything but a fully trusted network. |
| `SR_DOWNLOAD_PREFIX` | no | Path segment for download URLs; default `downloads`. |
| `SR_MAX_CONCURRENT_EXTRACTIONS` | no | Default `1` — matches legacy serialized-extraction behavior. |
| `SR_EXTRACT_TIMEOUT_SECONDS` | no | Default `300`; if you raise this, the `gunicorn.conf.py` worker timeout (330s, via `SR_GUNICORN_TIMEOUT`) must stay above it. |
| `SR_RETENTION_MAX_AGE_DAYS` | no | Default `7`; `0` disables age-based pruning of `alerts`. |
| `SR_RETENTION_MAX_TOTAL_BYTES` | no | Default `0` (disabled); set a byte cap if disk space is tight. |
| `SR_LOG_FORMAT` | no | `text` (default) or `json` — set `json` if logs feed a collector. |

- [ ] Double check `SR_PUBLIC_HOST` resolves to this host from wherever
      Sycope and download clients sit (DNS or `/etc/hosts`).

## 7. Generate the Basic-auth hash

```bash
docker run --rm caddy:2 caddy hash-password --plaintext 'yourpassword'
```

- [ ] Paste the output into `.env` as `BASIC_AUTH_HASH` (step 6) — do this
      before first bring-up, not after, since Caddy reads it at startup.

## 8. First bring-up

```bash
cd /opt/sycope-recorder
docker compose -f compose.yaml -f compose.dist.yaml up -d
```

Do **not** pass `--build` — the image is already local/pulled; `--build`
would try (and fail, with no source present) to build from `.`.

- [ ] `docker compose ps` — both `api` and `caddy` should be `Up`/`healthy`
      (the `api` healthcheck takes up to `start_period: 10s` to go green).
- [ ] `docker compose logs api` — no repeated tracebacks; a clean gunicorn
      boot line.
- [ ] `docker compose logs caddy` — confirms it obtained/generated its
      internal TLS cert for `SR_PUBLIC_HOST` without error.

## 9. Smoke test

```bash
# Unauthenticated health check
curl -k https://$SR_PUBLIC_HOST/healthz
# expect: {"status":"ok","timeline_dir_present":true,"output_dir_present":true}
```

- [ ] Both `*_present` fields are `true`. If `timeline_dir_present` is
      `false`, the bind mount from step 5 is wrong or empty — fix that
      before testing extraction.

```bash
curl -k -u "$BASIC_AUTH_USER:yourpassword" -X POST \
  "https://$SR_PUBLIC_HOST/extract?filter=full&before=30&after=30" \
  -H 'Content-Type: application/json' \
  -d '{"id":"smoke-test","clientIp":"10.0.0.10","serverIp":"10.0.0.20","serverPort":443,"protocolName":"tcp","unixTimestamp":<recent-unix-ts>}'
```

- [ ] Response body is a download URL (not an `ERROR:`/`NO BPF FILTER`
      string) — use a real recent timestamp/IPs that exist in the current
      rolling window, or expect `ERROR: npcapextract failed` (empty match)
      even on a fully working stack.
- [ ] Follow the returned URL with `-u` credentials and confirm the PCAP
      downloads.

`-k` above is only because Caddy's internal CA is self-signed; production
Sycope/client configs should trust that CA rather than skip verification
long-term.

## 10. Point Sycope at the deployment

- [ ] In Sycope, set the webhook action to
      `POST https://$SR_PUBLIC_HOST/extract?filter=full&before=360&after=360`
      (or your chosen filter/window) with the same Basic-auth credentials
      from step 6/7.
- [ ] If clients (Sycope or download consumers) can't be configured to
      trust Caddy's internal CA, they'll need `-k`/insecure-mode equivalents
      — flag this to whoever owns the Sycope config.

## 11. Post-deploy checklist

- [ ] **Persist `caddy_data`/`caddy_config` volumes.** They hold the
      internal CA and cert — losing them on a redeploy forces every client
      to re-trust a new cert. Don't `docker compose down -v` casually.
- [ ] **Confirm `restart: unless-stopped`** took effect (`docker inspect`
      on both containers) so the stack survives a host reboot.
- [ ] **Set a reminder to revisit `ALLOWED_IPS`** if left at the open
      default in step 6.
- [ ] Record the deployed image tag(s) somewhere (e.g. `docker inspect
      --format '{{.Config.Image}}'`) so a future redeploy/rollback knows
      what's currently running.

## 12. Updating later

```bash
# after loading/pulling a new image tag and bumping compose.dist.yaml's `image:`
docker compose -f compose.yaml -f compose.dist.yaml up -d
```

Compose recreates only the containers whose config/image changed —
`caddy_data`/`caddy_config`/`rolling`/`alerts` volumes are untouched. Re-run
the step 9 smoke test after every update before considering it done.
