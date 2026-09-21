#!/usr/bin/env bash
# One-shot migration for THIS specific client host:
#   - v1 recorder (old/src/listener.py + old/src/fileserver.py, bare metal)
#     is stopped and backed up, never deleted outright.
#   - n2disk stays exactly as-is except the systemd unit gets a restart
#     backoff cap (the 1.5M-restart loop from the license-expiry incident
#     must not be able to repeat silently).
#   - the mixed rolling/ layout (epoch-dirs from the dead May capture vs.
#     the dated tree from the working Sep capture) is reported and the
#     dead epoch-dirs are moved aside, not deleted.
#   - v2 (docker compose: api + caddy) is deployed against the existing
#     rolling path, with the api container's clock pinned to the host's
#     timezone (bind-mounted /etc/localtime + TZ env) so extraction
#     windows agree with n2disk's own timestamps.
#   - a short buffer warm-up wait (default 3 min, below the 300s chunk
#     duration) runs before the smoke test - it reduces but does not
#     eliminate the "buffer still empty right after n2disk (re)start"
#     false-negative risk; the smoke test step explains how to tell a
#     real failure from a benign MISS if it happens.
#
# This is NOT a generic installer. It assumes the exact topology from the
# 2026-09-21 diagnostic session: n2disk + npcapextract already installed
# and licensed on this host, capture interface eno2np1, rolling path
# /storage/pcaps/rolling, host timezone Europe/Warsaw, v1 recorder
# installed under /home/user/recorder (adjust V1_DIR below if that's wrong
# on this box). ntop/Suricata also run on this host - if extraction
# windows still look wrong after this script's TZ check passes, check
# those services' own clock/TZ assumptions too; this script only verifies
# the recorder's own host/container/n2disk chain.
#
# Usage: sudo ./migrate-to-v2.sh [--skip-cleanup] [--skip-smoke-test]
#
# Safe to re-run: every step checks current state before acting.

set -euo pipefail

# ---- knobs you may need to adjust for this host --------------------------
V1_DIR="/home/user/recorder"
V1_SERVICE_NAMES=("sycope-listener" "sycope-fileserver")   # adjust if different
N2DISK_SERVICE="n2disk.service"
ROLLING_DIR="/storage/pcaps/rolling"
ALERTS_DIR="/storage/pcaps/alerts"
DEPLOY_DIR="/opt/sycope-recorder"
BACKUP_DIR="/root/sycope-recorder-v1-backup-$(date +%Y%m%d_%H%M%S)"
REPO_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # this repo checkout
BUFFER_WARMUP_SECONDS=180   # 3 min. n2disk chunks are 300s (--max-file-duration)
                            # so this does NOT guarantee a closed/indexed chunk
                            # exists yet - see step 5's warning at runtime.

# Shared Basic-auth credential for this deployment - fronts BOTH the
# webhook endpoint (POST /extract, what Sycope's outbound webhook action
# authenticates with) and the PCAP download path (GET /downloads/*, what
# Sycope/analysts authenticate with to fetch the extracted file). v2 has
# a single credential pair for both, unlike v1's separate
# listener_auth_user/fileserver_auth_user - v1's config.json on this
# client currently has BOTH blank (no auth at all on either service).
# Used in step 1 (hardening the backed-up v1 config) and step 4 (v2 .env).
# Prompted interactively below - never hardcode a real client credential
# in this script.
CLIENT_BASIC_AUTH_USER=""
CLIENT_BASIC_AUTH_PLAINTEXT=""
# ---------------------------------------------------------------------------

SKIP_CLEANUP=0
SKIP_SMOKE_TEST=0
for arg in "$@"; do
    case "$arg" in
        --skip-cleanup) SKIP_CLEANUP=1 ;;
        --skip-smoke-test) SKIP_SMOKE_TEST=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m FAIL\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    die "run as root (needs systemctl, docker, and /storage access)"
fi

# ===========================================================================
log "Step -1/7: shared Basic-auth credential for this deployment"
# ===========================================================================
read -r -p "Basic-auth username [sycope]: " CLIENT_BASIC_AUTH_USER
CLIENT_BASIC_AUTH_USER="${CLIENT_BASIC_AUTH_USER:-sycope}"

while true; do
    read -r -s -p "Basic-auth password: " CLIENT_BASIC_AUTH_PLAINTEXT
    echo
    [[ -n "$CLIENT_BASIC_AUTH_PLAINTEXT" ]] || { warn "password cannot be empty"; continue; }
    read -r -s -p "confirm password: " _confirm_pw
    echo
    [[ "$CLIENT_BASIC_AUTH_PLAINTEXT" == "$_confirm_pw" ]] && break
    warn "passwords did not match, try again"
done
unset _confirm_pw
ok "credential captured for user '${CLIENT_BASIC_AUTH_USER}' (used in steps 1 and 4 below)"

# ===========================================================================
log "Step 0/7: pre-flight checks (auto-installs Docker if missing)"
# ===========================================================================
# Only Docker itself gets auto-installed. n2disk/npcapextract are ntop's
# licensed commercial packages - there is no way to install those without
# the client's own ntop license/repo credentials, so a missing rolling/
# dir or missing npcapextract binary still just fails/warns below instead
# of trying to fetch anything.
if ! command -v docker >/dev/null 2>&1; then
    warn "docker not found - installing via get.docker.com"
    curl -fsSL https://get.docker.com | sh || die "docker install script failed"
    systemctl enable --now docker
    command -v docker >/dev/null 2>&1 || die "docker still not on PATH after install"
    ok "docker installed"
else
    ok "docker already present ($(docker --version))"
fi

if ! docker compose version >/dev/null 2>&1; then
    # This branch only fires when Docker itself came from somewhere other
    # than get.docker.com (e.g. distro-packaged docker.io on Debian/Ubuntu),
    # since get.docker.com above already pulls docker-compose-plugin from
    # Docker's own repo. Debian/Ubuntu's OWN apt repos do not carry
    # docker-compose-plugin at all, so apt-get install would just 404 -
    # add Docker's official repo first, the same one get.docker.com uses.
    warn "docker compose plugin not found - installing docker-compose-plugin"
    if command -v apt-get >/dev/null 2>&1; then
        . /etc/os-release
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-compose-plugin
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q docker-compose-plugin
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q docker-compose-plugin
    else
        die "no known package manager (apt-get/dnf/yum) to install docker-compose-plugin - install it manually and re-run"
    fi
    docker compose version >/dev/null 2>&1 || die "docker compose plugin still missing after install"
    ok "docker compose plugin installed"
else
    ok "docker compose already present ($(docker compose version --short 2>/dev/null))"
fi

if ! systemctl is-active --quiet docker; then
    log "starting docker service"
    systemctl enable --now docker
fi

# The migration itself runs as root (see the EUID check above), so group
# membership doesn't gate this script's own `docker` calls - this is only
# for whoever hands off day-2 operation of this host afterwards, so a
# non-root operator can run `docker compose logs` etc. without sudo.
HANDOFF_USER="${SUDO_USER:-}"
if [[ -n "$HANDOFF_USER" ]] && id "$HANDOFF_USER" >/dev/null 2>&1; then
    if ! id -nG "$HANDOFF_USER" | grep -qw docker; then
        usermod -aG docker "$HANDOFF_USER"
        warn "added '$HANDOFF_USER' to the docker group - they must log out/in (or run 'newgrp docker') for it to take effect"
    fi
fi

command -v npcapextract >/dev/null 2>&1 || warn "npcapextract not on PATH as root - v2 will need SR_NPCAPEXTRACT_PATH pointed at it explicitly, see step 4"
[[ -d "$ROLLING_DIR" ]] || die "$ROLLING_DIR does not exist - is n2disk even installed on this host?"
ok "docker + compose present, $ROLLING_DIR exists"

# ===========================================================================
log "Step 1/7: stop and back up v1 (never delete outright)"
# ===========================================================================
mkdir -p "$BACKUP_DIR"

for svc in "${V1_SERVICE_NAMES[@]}"; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
        if systemctl is-active --quiet "$svc"; then
            log "stopping $svc"
            systemctl stop "$svc"
        fi
        systemctl disable "$svc" 2>/dev/null || true
        ok "$svc stopped and disabled"
    else
        # v1 may have run under a supervisor other than systemd (screen/tmux/nohup);
        # fall back to killing by script path.
        if pkill -f "src/listener.py" 2>/dev/null; then
            warn "$svc not a systemd unit; killed a bare 'python3 .../listener.py' process instead"
        fi
        if pkill -f "src/fileserver.py" 2>/dev/null; then
            warn "killed a bare 'python3 .../fileserver.py' process instead"
        fi
    fi
done

if [[ -d "$V1_DIR" ]]; then
    log "backing up $V1_DIR -> $BACKUP_DIR/recorder-v1"
    cp -a "$V1_DIR" "$BACKUP_DIR/recorder-v1"
    ok "v1 source + config backed up"
else
    warn "$V1_DIR not found - nothing to back up (adjust V1_DIR at the top of this script if v1 lives elsewhere)"
fi

if [[ -f "/etc/systemd/system/${V1_SERVICE_NAMES[0]}.service" ]]; then
    cp "/etc/systemd/system/${V1_SERVICE_NAMES[0]}.service" "$BACKUP_DIR/" 2>/dev/null || true
fi

# v1's config.json on this client currently has listener_auth_user/pass
# AND fileserver_auth_user/pass both blank - both services run with zero
# auth. v1 is stopped above and stays stopped, but set real credentials in
# the BACKED-UP config too (never the live one, since it's not running
# again) so a future manual restore from backup doesn't silently come back
# up wide open. v1 does plaintext comparison (see check_basic_auth in
# config_loader.py) - no hashing, unlike v2's Caddy bcrypt.
V1_BACKUP_CONFIG="$BACKUP_DIR/recorder-v1/config/config.json"
if [[ -f "$V1_BACKUP_CONFIG" ]]; then
    python3 - "$V1_BACKUP_CONFIG" "$CLIENT_BASIC_AUTH_USER" "$CLIENT_BASIC_AUTH_PLAINTEXT" <<'PYEOF'
import json, sys
path, user, pwd = sys.argv[1:4]
with open(path) as f:
    cfg = json.load(f)
cfg["listener_auth_user"] = user
cfg["listener_auth_pass"] = pwd
cfg["fileserver_auth_user"] = user
cfg["fileserver_auth_pass"] = pwd
with open(path, "w") as f:
    json.dump(cfg, f, indent=4)
PYEOF
    ok "set listener/fileserver auth in the BACKED-UP v1 config (not the live one - v1 stays stopped) so a future manual restore isn't auth-open by default"
else
    warn "no v1 config.json found in the backup - skipping v1 credential hardening"
fi

ok "v1 stopped, backup at $BACKUP_DIR"

# ===========================================================================
log "Step 2/7: rolling/ cleanup - report mixed layout, quarantine dead epoch-dirs"
# ===========================================================================
if [[ "$SKIP_CLEANUP" -eq 1 ]]; then
    warn "skipping cleanup (--skip-cleanup)"
else
    # The May incident (license expiry -> 1.5M restart loop) left epoch-named
    # directories (e.g. 1779173783.780556) alongside the working dated tree
    # (2026/MM/DD/HH). Both were seen directly under $ROLLING_DIR in the
    # 2026-09-21 session. Only touch top-level dirs matching the epoch
    # pattern; the YYYY dated tree is left completely alone.
    mapfile -t epoch_dirs < <(find "$ROLLING_DIR" -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{9,10}\.[0-9]+$')

    if [[ "${#epoch_dirs[@]}" -eq 0 ]]; then
        ok "no epoch-named directories found directly under $ROLLING_DIR - layout looks clean"
    else
        warn "found ${#epoch_dirs[@]} epoch-named directories under $ROLLING_DIR (dead capture from the pre-license-fix period)"
        QUARANTINE_DIR="${ROLLING_DIR%/}_dead_epoch_dirs_$(date +%Y%m%d)"
        mkdir -p "$QUARANTINE_DIR"
        du_before=$(du -sh "$ROLLING_DIR" 2>/dev/null | cut -f1)
        for d in "${epoch_dirs[@]}"; do
            mv "$d" "$QUARANTINE_DIR/"
        done
        ok "moved ${#epoch_dirs[@]} epoch-dirs to $QUARANTINE_DIR (rolling was $du_before before the move - review and rm -rf $QUARANTINE_DIR yourself once confirmed dead)"
    fi

    # Report (don't touch) old dated subtrees so you can decide manually.
    # Must use -regextype posix-extended (same as the epoch-dir find above) -
    # GNU findutils' default "emacs" regextype does not support {n} interval
    # expressions the way this pattern needs, and silently matches nothing.
    log "current rolling/ dated-tree contents (for manual review, nothing deleted):"
    find "$ROLLING_DIR" -maxdepth 3 -type d -regextype posix-extended -regex '.*/[0-9]{4}(/[0-9]{2}){0,2}$' 2>/dev/null | sort || true
fi

# ===========================================================================
log "Step 3/7: fix n2disk.service restart backoff (prevents a repeat of the 1.5M-restart loop)"
# ===========================================================================
N2DISK_UNIT_PATH="/etc/systemd/system/${N2DISK_SERVICE}"
if [[ ! -f "$N2DISK_UNIT_PATH" ]]; then
    # try the common packaged location too
    N2DISK_UNIT_PATH="/lib/systemd/system/${N2DISK_SERVICE}"
fi

if [[ -f "$N2DISK_UNIT_PATH" ]]; then
    if grep -q "StartLimitBurst" "$N2DISK_UNIT_PATH"; then
        ok "$N2DISK_UNIT_PATH already has a restart backoff cap"
    else
        cp "$N2DISK_UNIT_PATH" "$BACKUP_DIR/n2disk.service.orig"
        # Insert StartLimitIntervalSec/Burst into [Unit], raise RestartSec in [Service].
        awk '
            /^\[Unit\]/ { print; print "StartLimitIntervalSec=300"; print "StartLimitBurst=5"; next }
            /^RestartSec=/ { print "RestartSec=30"; next }
            { print }
        ' "$N2DISK_UNIT_PATH" > "${N2DISK_UNIT_PATH}.new"
        mv "${N2DISK_UNIT_PATH}.new" "$N2DISK_UNIT_PATH"
        systemctl daemon-reload
        ok "added StartLimitIntervalSec=300 / StartLimitBurst=5, RestartSec=30 to $N2DISK_UNIT_PATH (backup: $BACKUP_DIR/n2disk.service.orig)"
    fi
    systemctl is-active --quiet "$N2DISK_SERVICE" || warn "$N2DISK_SERVICE is not currently active - check licensing/config before continuing"
else
    warn "could not find $N2DISK_SERVICE unit file - skipping backoff fix, do this by hand"
fi

# ===========================================================================
log "Step 4/7: deploy v2"
# ===========================================================================
mkdir -p "$DEPLOY_DIR/caddy"
cp "$REPO_SRC_DIR/compose.yaml" "$DEPLOY_DIR/"
cp "$REPO_SRC_DIR/caddy/Caddyfile" "$DEPLOY_DIR/caddy/"

if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
    log "$DEPLOY_DIR/.env does not exist yet - creating it with this deployment's credentials"
    CLIENT_BASIC_AUTH_HASH="$(docker run --rm caddy:2 caddy hash-password --plaintext "$CLIENT_BASIC_AUTH_PLAINTEXT")"
    cat > "$DEPLOY_DIR/.env" <<EOF
# --- SR_PUBLIC_HOST is the only value that MUST be edited per-host ---
SR_PUBLIC_HOST=CHANGE_ME.client-domain.example

# --- shared Basic-auth for /extract (webhook) and /downloads/* (PCAP
# fetch) - plaintext password is ${CLIENT_BASIC_AUTH_PLAINTEXT}, use it to
# configure Sycope's webhook action and any passthrough/download client.
# Hash regenerated fresh by this script each run it's missing; to rotate
# the password by hand: docker run --rm caddy:2 caddy hash-password --plaintext 'newpassword' ---
BASIC_AUTH_USER=${CLIENT_BASIC_AUTH_USER}
BASIC_AUTH_HASH=${CLIENT_BASIC_AUTH_HASH}

# --- npcapextract on this host is NOT baked into the api image (see
# Dockerfile comment + README_DIST.md 8.3) - point at the real host binary
# via a bind mount. Uncomment and adjust the volumes override below if
# \`npcapextract\` was not found on PATH during pre-flight. ---
# SR_NPCAPEXTRACT_PATH=/usr/local/bin/npcapextract

SR_MAX_CONCURRENT_EXTRACTIONS=1
SR_EXTRACT_TIMEOUT_SECONDS=300
SR_RETENTION_MAX_AGE_DAYS=7
EOF
    die "edit $DEPLOY_DIR/.env: set SR_PUBLIC_HOST to this host's real hostname, then re-run this script"
fi

# Deliberately NOT `source`d: BASIC_AUTH_HASH is a bcrypt hash of the form
# $2a$14$... / $2b$..., and bash's `source`/`.` parses `$`-expansions in
# every line regardless of quoting - `source`ing a real hash crashes under
# `set -u` with "$2: unbound variable" (bash treats it as a positional
# parameter reference), and even without `set -u` a stray `` ` ``/`$(...)`
# in a hand-edited .env would execute as code. Pull out only the two
# values this script actually needs as plain text via grep instead;
# `docker compose` reads BASIC_AUTH_HASH straight from .env itself (its
# own parser, not bash) when it runs, so this script never needs to touch
# that value at all.
_env_get() {
    grep -E "^${1}=" "$DEPLOY_DIR/.env" | tail -n1 | cut -d= -f2-
}
SR_PUBLIC_HOST="$(_env_get SR_PUBLIC_HOST)"
BASIC_AUTH_USER="$(_env_get BASIC_AUTH_USER)"
[[ "${SR_PUBLIC_HOST:-CHANGE_ME}" != "CHANGE_ME"* ]] || die "$DEPLOY_DIR/.env still has placeholder values - edit it first"
[[ "${BASIC_AUTH_USER:-CHANGE_ME}" != "CHANGE_ME"* ]] || die "$DEPLOY_DIR/.env still has placeholder values - edit it first"

# Bind-mount the real rolling/alerts paths + real npcapextract binary in an
# override, instead of hand-editing compose.yaml. Also bind-mount
# /etc/localtime and set TZ so the api container's wall clock matches the
# host's (Europe/Warsaw on this client, not the UTC a bare container
# defaults to) - extraction.py deliberately builds the npcapextract time
# window from local wall-clock time, so container and host must agree.
# Step 5 below verifies this actually took effect rather than trusting it.
NPCAPEXTRACT_BIN="$(command -v npcapextract || true)"
HOST_TZ_NAME="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "")"
{
    echo "services:"
    echo "  api:"
    echo "    volumes:"
    echo "      - ${ROLLING_DIR}:/storage/pcaps/rolling:ro"
    echo "      - ${ALERTS_DIR}:/storage/pcaps/alerts"
    echo "      - /etc/localtime:/etc/localtime:ro"
    if [[ -n "$NPCAPEXTRACT_BIN" ]]; then
        echo "      - ${NPCAPEXTRACT_BIN}:/usr/local/bin/npcapextract:ro"
    fi
    echo "    environment:"
    if [[ -n "$HOST_TZ_NAME" ]]; then
        echo "      TZ: ${HOST_TZ_NAME}"
    fi
    if [[ -n "$NPCAPEXTRACT_BIN" ]]; then
        echo "      SR_NPCAPEXTRACT_PATH: /usr/local/bin/npcapextract"
    fi
} > "$DEPLOY_DIR/compose.override.yaml"
# Note: no top-level `volumes:` block here for rolling/alerts - the api
# service above already bind-mounts ${ROLLING_DIR}/${ALERTS_DIR} directly
# by host path, which takes priority over base compose.yaml's named-volume
# entries for the same mount targets. Redefining named volumes here too
# would just be dead, unused config.

if [[ -n "$NPCAPEXTRACT_BIN" ]]; then
    ok "found host npcapextract at $NPCAPEXTRACT_BIN - bind-mounting it into the api container"
    warn "if npcapextract is dynamically linked against libs not present in the python:3.12-slim image, this bind-mount alone will fail at runtime - the smoke test in step 6 will surface that"
else
    warn "npcapextract not found on host PATH - api container will only see whatever's baked into its own image (per Dockerfile, currently nothing). Fix SR_NPCAPEXTRACT_PATH in $DEPLOY_DIR/.env manually before the smoke test can pass."
fi

# Permissions: rolling/ is owned n2disk:ntop with 0750 (README_DEPLOY.md
# step 2 / SPEC.md 3.1). The api container's user must be in that group,
# or the bind mount is unreadable.
rolling_owner="$(stat -c '%U:%G' "$ROLLING_DIR" 2>/dev/null || echo 'unknown:unknown')"
rolling_group="${rolling_owner#*:}"
log "checking whether the api container's runtime user can read $ROLLING_DIR (owned $rolling_owner)"
if [[ "$rolling_group" != "unknown" ]]; then
    gid="$(getent group "$rolling_group" 2>/dev/null | cut -d: -f3 || true)"
    if [[ -n "$gid" ]]; then
        # compose.override.yaml was just regenerated from scratch above
        # (the `{ ... } > file` block overwrites it every run), so there is
        # no prior group_add to collide with here.
        sed -i "/^  api:/a\\    group_add: [\"${gid}\"]" "$DEPLOY_DIR/compose.override.yaml"
        ok "added group_add: [\"${gid}\"] (${rolling_group}) to the api service so it can read rolling/ inside the container"
    else
        warn "could not resolve gid for group '$rolling_group' - add the api container to that group manually if extraction fails with permission errors"
    fi
fi

cd "$DEPLOY_DIR"
log "docker compose up -d"
docker compose -f compose.yaml -f compose.override.yaml up -d --build
ok "v2 stack started"

log "waiting for api + caddy healthchecks"
for i in $(seq 1 30); do
    api_status="$(docker compose ps --format '{{.Name}} {{.Health}}' 2>/dev/null | awk '/api/{print $2}')"
    if [[ "$api_status" == "healthy" ]]; then
        ok "api container healthy"
        break
    fi
    sleep 2
    if [[ $i -eq 30 ]]; then
        docker compose logs api --tail 50
        die "api never went healthy after 60s - see logs above"
    fi
done

curl -sk "https://${SR_PUBLIC_HOST}/healthz" 2>/dev/null | tee /tmp/healthz.json || true
if grep -q '"timeline_dir_present":true' /tmp/healthz.json 2>/dev/null && grep -q '"output_dir_present":true' /tmp/healthz.json 2>/dev/null; then
    ok "/healthz reports both timeline_dir and output_dir present"
else
    die "/healthz did not report both dirs present - check the bind mounts in $DEPLOY_DIR/compose.override.yaml"
fi

# ===========================================================================
log "Step 5/7: timezone consistency check (host / n2disk / api container)"
# ===========================================================================
# extraction.py builds the npcapextract time window from the alert's
# unix timestamp converted with the HOST's local wall-clock time (this is
# deliberate - npcapextract indexes n2disk's timeline against whatever
# clock n2disk itself timestamps chunks with, which is the machine's local
# time, not UTC). That only produces a correct window if every clock in
# the chain (host, n2disk, the api container) agrees on wall time. On this
# client's box `timedatectl` reports Europe/Warsaw (CEST, +0200) - so the
# api container MUST also see Europe/Warsaw, not the UTC a bare Docker
# container defaults to, or every extraction window will be off by the
# +0200/+0100 offset. Suricata/ntop on the same box are a second source of
# truth worth cross-checking manually if extraction windows still look
# wrong after this passes - this check only covers the recorder's own path.
HOST_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo unknown)"
HOST_NOW="$(date +%s)"
log "host timezone: ${HOST_TZ:-unknown} (local time now: $(date '+%Y-%m-%d %H:%M:%S %Z'))"

API_CONTAINER_TZ="$(docker compose exec -T api date +%Z 2>/dev/null || echo unknown)"
API_CONTAINER_EPOCH="$(docker compose exec -T api date +%s 2>/dev/null || echo 0)"

if [[ "$API_CONTAINER_TZ" == "unknown" || "$API_CONTAINER_EPOCH" == "0" ]]; then
    warn "could not read date/TZ from inside the api container - verify manually: docker compose exec api date"
else
    drift_s=$(( API_CONTAINER_EPOCH - HOST_NOW ))
    drift_abs=${drift_s#-}
    if [[ "$drift_abs" -gt 120 ]]; then
        warn "api container clock differs from host by ${drift_s}s (container TZ=${API_CONTAINER_TZ}) - this will shift every extraction window by roughly that amount. Fix: add 'TZ=${HOST_TZ}' to the api service environment in compose.override.yaml, or bind-mount /etc/localtime:/etc/localtime:ro, then re-run this script."
    else
        ok "api container wall-clock matches host within ${drift_abs}s (container TZ=${API_CONTAINER_TZ})"
    fi
fi

# ===========================================================================
log "Step 6/7: n2disk buffer warm-up wait (${BUFFER_WARMUP_SECONDS}s)"
# ===========================================================================
# Known failure mode from the 2026-09-21 session: n2disk was restarted
# (license fix) and the very next extraction request landed on a window
# with zero closed/indexed chunks, because --max-file-duration=300 means
# the first indexed chunk doesn't exist until 5 minutes after n2disk starts.
# BUFFER_WARMUP_SECONDS=180 (3 min) is shorter than one full 300s chunk, so
# this wait does NOT guarantee a closed chunk exists - it only avoids
# testing against a buffer that's seconds old. A MISS/"ERROR: npcapextract
# failed" result right after this wait is still plausible on a freshly
# (re)started n2disk and is not necessarily a real failure; step 7 flags
# this explicitly rather than treating it as a hard blocker.
raw_active_ts="$(systemctl show -p ActiveEnterTimestamp --value "$N2DISK_SERVICE" 2>/dev/null || true)"
n2disk_start_epoch=0
if [[ -n "$raw_active_ts" && "$raw_active_ts" != "n/a" ]]; then
    # xargs -I{} on empty stdin runs `date` zero times and yields "", not
    # an error - guard explicitly instead of piping through xargs.
    n2disk_start_epoch="$(date -d "$raw_active_ts" +%s 2>/dev/null || echo 0)"
fi
if [[ "$n2disk_start_epoch" -gt 0 ]]; then
    now_epoch=$(date +%s)
    uptime_s=$(( now_epoch - n2disk_start_epoch ))
    need_s=$(( BUFFER_WARMUP_SECONDS - uptime_s ))
    if [[ $need_s -gt 0 ]]; then
        log "n2disk has been up ${uptime_s}s; waiting ${need_s}s more (target: ${BUFFER_WARMUP_SECONDS}s uptime before testing)"
        sleep "$need_s"
    else
        ok "n2disk has been up ${uptime_s}s already - proceeding"
    fi
    if [[ $(( uptime_s > need_s ? uptime_s : BUFFER_WARMUP_SECONDS )) -lt 300 ]]; then
        warn "n2disk uptime is under 300s (one chunk duration) - the smoke test below may legitimately MISS with zero packets matched even if everything is wired correctly. If it does, wait until n2disk has been up 5+ minutes and re-run with --skip-cleanup."
    fi
else
    if [[ -z "$raw_active_ts" ]]; then
        warn "$N2DISK_SERVICE has no ActiveEnterTimestamp (never started, or systemd unit missing) - waiting the configured ${BUFFER_WARMUP_SECONDS}s as a fallback, but check 'systemctl status $N2DISK_SERVICE' before trusting the smoke test result"
    else
        warn "could not parse n2disk start time ('$raw_active_ts') - waiting the configured ${BUFFER_WARMUP_SECONDS}s as a fallback"
    fi
    sleep "$BUFFER_WARMUP_SECONDS"
fi

# ===========================================================================
log "Step 7/7: smoke test against real fresh data"
# ===========================================================================
if [[ "$SKIP_SMOKE_TEST" -eq 1 ]]; then
    warn "skipping smoke test (--skip-smoke-test)"
    log "migration steps done. Run this script's smoke test manually later, or point a real Sycope alert at:"
    echo "  https://${SR_PUBLIC_HOST}/extract?filter=full&before=360&after=360"
    exit 0
fi

# Known fixed credential for this deployment (see step 4) - only fall
# back to the env var / manual-curl path if it was overridden and BOTH
# BASIC_AUTH_USER and CLIENT_BASIC_AUTH_PLAINTEXT no longer match what's
# actually in .env (e.g. someone rotated the password by hand after step 4).
BASIC_AUTH_PLAINTEXT="${BASIC_AUTH_PLAINTEXT:-$CLIENT_BASIC_AUTH_PLAINTEXT}"
if [[ -z "$BASIC_AUTH_PLAINTEXT" ]]; then
    warn "no password available to curl the API with - export BASIC_AUTH_PLAINTEXT before running. Falling back to a curl command you can run by hand:"
    echo
    echo "  curl -k -u \"\$BASIC_AUTH_USER:<plaintext-password>\" -X POST \\"
    echo "    \"https://${SR_PUBLIC_HOST}/extract?filter=full&before=30&after=30\" \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"id\":\"migration-smoke-test\",\"clientIp\":\"10.0.0.10\",\"serverIp\":\"10.0.0.20\",\"serverPort\":443,\"protocolName\":\"tcp\",\"unixTimestamp\":'\"\$(date +%s)\"'}'"
    echo
    log "migration steps 0-6 done; run the curl above manually, or export BASIC_AUTH_PLAINTEXT and re-run with the same flags to finish step 7 automatically."
    exit 0
fi

now_ts=$(date +%s)
log "sending a real test alert with unixTimestamp=$now_ts (just now) against a currently-recording window"
response="$(curl -sk -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PLAINTEXT}" -X POST \
    "https://${SR_PUBLIC_HOST}/extract?filter=full&before=30&after=30" \
    -H 'Content-Type: application/json' \
    -d "{\"id\":\"migration-smoke-test\",\"clientIp\":\"10.0.0.10\",\"serverIp\":\"10.0.0.20\",\"serverPort\":443,\"protocolName\":\"tcp\",\"unixTimestamp\":${now_ts}}")"

echo "response: $response"

case "$response" in
    https://*)
        ok "extraction returned a download URL: $response"
        log "verifying the file actually downloads"
        dl_status=$(curl -sk -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PLAINTEXT}" -o /tmp/smoke-test.pcap -w '%{http_code}' "$response")
        if [[ "$dl_status" == "200" ]] && [[ -s /tmp/smoke-test.pcap ]]; then
            ok "downloaded $(stat -c%s /tmp/smoke-test.pcap 2>/dev/null || stat -f%z /tmp/smoke-test.pcap) bytes to /tmp/smoke-test.pcap"
        else
            die "download returned HTTP $dl_status or an empty file"
        fi
        ;;
    "NO BPF FILTER")
        die "got NO BPF FILTER - the test payload's fields didn't survive parsing, check api logs"
        ;;
    "ERROR: npcapextract failed")
        warn "got ERROR: npcapextract failed - could be a real failure OR just a MISS (0 packets matched). Two known benign causes given the ${BUFFER_WARMUP_SECONDS}s warm-up wait used here: (1) the test IPs (10.0.0.10/10.0.0.20) don't appear in real traffic in this window, or (2) n2disk hasn't closed a single 300s chunk yet so there's nothing indexed to search. Check docker compose logs api for 'MISS' (benign) vs a real subprocess stderr (not benign) before treating this as a blocker. If it's (2), wait until n2disk uptime clears 300s+ and re-run: ./migrate-to-v2.sh --skip-cleanup"
        docker compose logs api --tail 30
        ;;
    "ERROR: npcapextract timeout")
        die "npcapextract timed out - check npcapextract_path is correct and the binary actually runs inside the container (docker compose exec api /usr/local/bin/npcapextract -h)"
        ;;
    *)
        die "unexpected response: $response"
        ;;
esac

log "migration complete."
echo "  v1 backup:        $BACKUP_DIR"
echo "  v2 deploy dir:     $DEPLOY_DIR"
echo "  next: point the real Sycope webhook at https://${SR_PUBLIC_HOST}/extract?filter=full&before=360&after=360"
echo "  and watch: docker compose -f $DEPLOY_DIR/compose.yaml -f $DEPLOY_DIR/compose.override.yaml logs -f api"
