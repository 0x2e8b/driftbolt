# Building and Shipping a Distribution

This document is for whoever packages the `api` service for a target host —
it is not needed for local development (see `README.md` for that).

The goal of a "dist" is a **pre-built `api` Docker image** plus the small set
of files a target host needs alongside it (`compose.yaml`, `caddy/Caddyfile`,
an `.env`). The target host never needs the source tree, `uv`, or a Python
toolchain — it only needs Docker.

## 1. Build the image

```bash
# Tag with something traceable back to source (git sha shown here).
TAG=$(git rev-parse --short HEAD)
docker build -t sycope-recorder-api:$TAG .
```

The `Dockerfile` build stage needs network access to pull `python:3.12-slim`,
`ghcr.io/astral-sh/uv:latest`, and the locked dependencies — do this on a
machine with normal internet access, not on an air-gapped target.

`caddy:2` is used as-is (no local Dockerfile) — pull it too so both images can
travel together:

```bash
docker pull caddy:2
```

## 2. Get the images to the target host

Pick one, depending on whether the target host can reach a registry:

**A. Registry (preferred when available)**

```bash
docker tag sycope-recorder-api:$TAG your-registry.example.com/sycope-recorder-api:$TAG
docker push your-registry.example.com/sycope-recorder-api:$TAG
docker tag caddy:2 your-registry.example.com/caddy:2
docker push your-registry.example.com/caddy:2
```

The target host then just needs `docker login` + `docker compose pull`.

**B. Offline transfer (no registry reachable from the target)**

```bash
docker save sycope-recorder-api:$TAG -o sycope-recorder-api.tar
docker save caddy:2 -o caddy.tar
```

Copy the two tarballs to the target host (`scp`/`rsync`) along with the dist
folder from step 3, then on the target:

```bash
docker load -i sycope-recorder-api.tar
docker load -i caddy.tar
```

## 3. Assemble the dist folder

The target host needs these files from the repo (nothing else — no `.git`,
`tests/`, `docs/`, `old/`, `.venv/`):

```
compose.yaml
caddy/Caddyfile
```

**`compose.yaml` currently builds the `api` image from source (`build: .`).**
For a pre-built-image dist, repoint it at the tag you built/loaded instead —
either edit the `api` service in place on the target, or ship an override
file, e.g. `compose.dist.yaml`:

```yaml
services:
  api:
    build: !reset null
    image: sycope-recorder-api:REPLACE_WITH_TAG   # or the registry path from step 2A
```

and run with `docker compose -f compose.yaml -f compose.dist.yaml up -d`
(no `--build` — the image is already local).

## 4. Deploy on the target host

Same runtime steps as `README.md`'s quickstart — required env vars
(`SR_PUBLIC_HOST`, `BASIC_AUTH_USER`, `BASIC_AUTH_HASH`, optionally
`ALLOWED_IPS`) still apply, and are unrelated to how the image was built:

```bash
docker run --rm caddy:2 caddy hash-password --plaintext 'yourpassword'
export SR_PUBLIC_HOST=recorder.example.com
export BASIC_AUTH_USER=sycope
export BASIC_AUTH_HASH='<paste the hash>'
docker compose -f compose.yaml -f compose.dist.yaml up -d
```

---

# Adding the Recorder (n2disk) to Docker Compose

`compose.yaml` has a commented-out `recorder` placeholder. It is commented
out because containerizing n2disk was deliberately deferred (design doc
§8.3/§8.4) — the pieces below are what's still missing before it can be
uncommented and used, not just a copy/paste.

## Open decisions to make first

1. **Is n2disk containerized at all, or does it stay on the host?**
   n2disk needs raw access to a physical NIC; on many hosts it's simpler to
   keep running it via the existing systemd unit (`docs/reference/n2disk.service`)
   and only share the filesystem with the containers. If so, skip the
   `recorder` compose service entirely and go straight to "Volume wiring"
   below.
   If it *is* containerized, you need an image with n2disk installed — there
   is no public `n2disk` image referenced anywhere in this repo; you'll be
   building one (ntop's install packages aren't redistributable without
   checking their licensing terms).

2. **Where does `npcapextract` live?** (design §8.3, still open) Either:
   - bundled into the `api` image — add an install/`COPY` step to the
     `Dockerfile` where the comment at line 17 currently marks this as
     deferred, or
   - invoked inside the `recorder` container, with the `api` container
     shelling out to it via a shared volume/exec path (more moving parts,
     only worth it if `recorder` already has the ntop toolchain installed).

## Volume wiring

The `rolling` volume in `compose.yaml` is currently a Docker-managed named
volume. If n2disk keeps running on the host (decision 1), change it to a
bind mount of n2disk's actual output path so both sides see the same files:

```yaml
volumes:
  rolling:
    driver: local
    driver_opts:
      type: none
      device: /storage/pcaps/rolling
      o: bind
```

**Permissions:** the rolling directory is owned by `n2disk:ntop` on the host
(SPEC §3.1/§9, `old/README.md` Troubleshooting). Whatever user the `api`
container runs `npcapextract` as must be able to read it — map/add that UID
to the `ntop` group on the host, or adjust the bind mount's permissions.
This is the most common source of "no extracted PCAPs" failures per the
legacy troubleshooting notes.

## If containerizing the recorder

Fill in the commented block in `compose.yaml`:

```yaml
recorder:
  image: <your n2disk image>
  restart: unless-stopped
  network_mode: host        # needs the physical interface, not a bridge
  cap_add: ["NET_RAW", "NET_ADMIN"]
  volumes:
    - rolling:/storage/pcaps/rolling
    - ./docs/reference/n2disk.conf:/etc/n2disk/n2disk.conf:ro
```

- `network_mode: host` is required for capture — n2disk needs to see the raw
  interface, not a virtual bridge NIC.
- `docs/reference/n2disk.conf` has `-i=ens18` — replace with the actual
  capture interface on the target host before mounting it in.
- No `depends_on` is needed between `recorder` and `api`: coordination is
  filesystem-only (design §2.2/§8.3) — the api container just needs the
  volume mounted and readable whenever an alert arrives, there's no startup
  ordering requirement.

## Verify end-to-end

1. Confirm the recorder (containerized or host) is writing 5-minute rolling
   files and a timeline index into the shared `rolling` path.
2. Confirm the `api` container can read that path (check ownership/group
   from "Volume wiring" above) and that `npcapextract` is resolvable
   (`npcapextract_path` / `PATH`, per decision 2).
3. Send a real `POST /extract` and confirm a non-empty PCAP appears in
   `alerts` and downloads through Caddy — this exercises the full chain, not
   just the individually mounted pieces.
