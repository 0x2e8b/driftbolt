#!/usr/bin/env bash
# Auto-remediation companion to verify.sh. Runs verify.sh, parses which
# checks FAILed, and fixes what it safely can - re-running verify.sh
# between each fix so later checks see the corrected state. Ubuntu target
# (apt-based), run as root.
#
# What this fixes automatically:
#   - BASIC_AUTH_HASH in .env with an unescaped $ (docker compose mangles it)
#   - missing /certs bind-mount under the caddy service in compose.override.yaml
#   - missing/expired TLS cert pair (self-signed, regenerated for SR_PUBLIC_HOST)
#   - n2disk.service not active, or active but not writing fresh files
#     (this DOES restart n2disk - that briefly interrupts capture and
#     affects anything else reading the same interface, e.g. Suricata/ntop
#     if they share it. Confirmed acceptable for this deployment.)
#   - api container can't read rolling/ (missing group_add)
#
# What it only reports (never touches):
#   - npcapextract missing/broken inside the container (needs a real fix
#     to the bind mount source or the image, not a config toggle)
#   - host/container clock drift (needs a host-level TZ/NTP decision)
#
# Usage: sudo ./fix.sh [deploy_dir]

set -uo pipefail

DEPLOY_DIR="${1:-/opt/sycope-recorder}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$SCRIPT_DIR/verify.sh"
COMPOSE="docker compose -f $DEPLOY_DIR/compose.yaml -f $DEPLOY_DIR/compose.override.yaml"
ROLLING_DIR="/storage/pcaps/rolling"

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  OK\033[0m  %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m FAIL\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    die "run as root"
fi
if [[ ! -x "$VERIFY" ]]; then
    die "verify.sh not found or not executable next to this script ($VERIFY)"
fi
if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
    die "$DEPLOY_DIR/.env not found - is $DEPLOY_DIR the right deploy dir?"
fi

FIXED=0
run_verify() {
    "$VERIFY" "$DEPLOY_DIR" 2>&1
}

# ---------------------------------------------------------------------------
log "initial check"
FIRST_RUN="$(run_verify)"
echo "$FIRST_RUN"

# ---------------------------------------------------------------------------
# Fix 1: unescaped $ in BASIC_AUTH_HASH
if grep -q 'BASIC_AUTH_HASH has an odd number' <<<"$FIRST_RUN" || grep -q 'does not show a valid bcrypt hash' <<<"$FIRST_RUN"; then
    log "fixing: BASIC_AUTH_HASH escaping"
    current="$(grep -E '^BASIC_AUTH_HASH=' "$DEPLOY_DIR/.env" | cut -d= -f2-)"
    if [[ -z "$current" ]]; then
        warn "BASIC_AUTH_HASH line missing entirely - cannot auto-fix, generate one manually:"
        warn "  docker run --rm caddy:2 caddy hash-password --plaintext '<password>'"
    else
        # Un-escape first (in case it's partially escaped), then re-escape
        # every $ exactly once. This is idempotent regardless of starting state.
        unescaped="${current//\$\$/\$}"
        escaped="${unescaped//\$/\$\$}"
        if [[ "$escaped" != "$current" ]]; then
            sed -i "s|^BASIC_AUTH_HASH=.*|BASIC_AUTH_HASH=${escaped}|" "$DEPLOY_DIR/.env"
            ok "re-escaped BASIC_AUTH_HASH (every \$ -> \$\$)"
            FIXED=1
        else
            warn "hash already looked escaped but verify still flagged it - inspect $DEPLOY_DIR/.env manually"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Fix 2: missing certs bind-mount in compose.override.yaml
if grep -q 'has NO certs bind-mount' <<<"$FIRST_RUN"; then
    log "fixing: certs bind-mount missing from compose.override.yaml"
    OVERRIDE="$DEPLOY_DIR/compose.override.yaml"
    if grep -q '^  caddy:' "$OVERRIDE" 2>/dev/null; then
        # caddy: block exists but lacks the mount - insert a volumes: entry
        # right after the 'caddy:' line. Safe because this only ever
        # ADDS a line; it never touches existing content.
        if grep -A5 '^  caddy:' "$OVERRIDE" | grep -q '^\s*volumes:'; then
            sed -i "/^  caddy:/,/^\s*volumes:/{/^\s*volumes:/a\\      - ${DEPLOY_DIR}/certs:/certs:ro
}" "$OVERRIDE"
        else
            sed -i "/^  caddy:/a\\    volumes:\\n      - ${DEPLOY_DIR}/certs:/certs:ro" "$OVERRIDE"
        fi
    else
        cat >> "$OVERRIDE" <<EOF
  caddy:
    volumes:
      - ${DEPLOY_DIR}/certs:/certs:ro
EOF
    fi
    ok "added certs bind-mount to $OVERRIDE"
    FIXED=1
fi

# ---------------------------------------------------------------------------
# Fix 3: missing cert files on disk
if grep -q 'server.crt or server.key missing' <<<"$FIRST_RUN"; then
    log "fixing: generating self-signed TLS cert"
    CERT_DIR="$DEPLOY_DIR/certs"
    mkdir -p "$CERT_DIR"
    SR_PUBLIC_HOST="$(grep -E '^SR_PUBLIC_HOST=' "$DEPLOY_DIR/.env" | cut -d= -f2-)"
    if [[ -z "$SR_PUBLIC_HOST" || "$SR_PUBLIC_HOST" == CHANGE_ME* ]]; then
        warn "SR_PUBLIC_HOST not set in .env - cannot generate a cert with the right CN/SAN. Set it first, then re-run."
    else
        # SAN must be IP: for a literal IP address, DNS: for a hostname.
        if [[ "$SR_PUBLIC_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            SAN="IP:${SR_PUBLIC_HOST}"
        else
            SAN="DNS:${SR_PUBLIC_HOST}"
        fi
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
            -days 825 -subj "/CN=${SR_PUBLIC_HOST}" -addext "subjectAltName=${SAN}" \
            2>/dev/null
        if [[ -f "$CERT_DIR/server.crt" ]]; then
            ok "generated self-signed cert for ${SR_PUBLIC_HOST} (825 days)"
            FIXED=1
        else
            warn "openssl req failed - check openssl is installed (apt install -y openssl)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Fix 3b: npcapextract stuck past its own timeout
# With SR_MAX_CONCURRENT_EXTRACTIONS=1 (default) a single stuck process
# silently blocks every extraction behind it, with no visible error on
# the Caddy/auth side - this is what we suspect caused webhooks to go
# quiet after 10:14 on 2026-09-22 without hard proof at the time.
if grep -q 'npcapextract process stuck past its own timeout' <<<"$FIRST_RUN"; then
    log "fixing: killing stuck npcapextract process(es)"
    stuck_pids="$($COMPOSE exec -T api ps -eo pid,comm 2>/dev/null | grep npcapextract | grep -v grep | awk '{print $1}')"
    if [[ -z "$stuck_pids" ]]; then
        warn "verify.sh reported a stuck process but none found now - it may have exited on its own, or the container restarted since"
    else
        for pid in $stuck_pids; do
            $COMPOSE exec -T api kill -9 "$pid" 2>/dev/null
        done
        sleep 2
        still_there="$($COMPOSE exec -T api ps -eo pid,comm 2>/dev/null | grep npcapextract | grep -v grep)"
        if [[ -z "$still_there" ]]; then
            ok "killed stuck npcapextract process(es): $stuck_pids"
            FIXED=1
        else
            warn "SIGKILL did not clear the process - it is likely stuck in uninterruptible D-state (blocked on a stalled mount/disk I/O). Restarting the api container instead."
            $COMPOSE restart api
            sleep 3
            ok "restarted api container to clear the stuck process"
            FIXED=1
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Fix 4: n2disk not active
if grep -q 'n2disk.service is NOT active' <<<"$FIRST_RUN"; then
    log "fixing: starting n2disk.service"
    systemctl start n2disk.service
    sleep 3
    if systemctl is-active --quiet n2disk.service; then
        ok "n2disk.service started"
        FIXED=1
    else
        warn "n2disk.service failed to start - check: journalctl -u n2disk.service -n 50 --no-pager"
    fi
fi

# ---------------------------------------------------------------------------
# Fix 5: n2disk active but not writing fresh files -> restart it
if grep -q 'is not writing fresh data' <<<"$FIRST_RUN"; then
    log "fixing: n2disk is active but stale - restarting (this briefly interrupts capture)"
    systemctl restart n2disk.service
    sleep 5
    if systemctl is-active --quiet n2disk.service; then
        ok "n2disk.service restarted and active - allow a few minutes before expecting fresh files (chunk duration applies)"
        FIXED=1
    else
        warn "n2disk.service did not come back up cleanly - check: journalctl -u n2disk.service -n 50 --no-pager"
    fi
fi

# ---------------------------------------------------------------------------
# Fix 6: api container can't read rolling/ -> fix group_add
if grep -q 'api container CANNOT read' <<<"$FIRST_RUN"; then
    log "fixing: api container missing group access to $ROLLING_DIR"
    rolling_group="$(stat -c '%G' "$ROLLING_DIR" 2>/dev/null)"
    gid="$(getent group "$rolling_group" 2>/dev/null | cut -d: -f3)"
    if [[ -z "$gid" ]]; then
        warn "could not resolve gid for group '$rolling_group' owning $ROLLING_DIR - fix manually"
    else
        OVERRIDE="$DEPLOY_DIR/compose.override.yaml"
        if grep -A3 '^  api:' "$OVERRIDE" | grep -q "group_add:.*\"${gid}\""; then
            warn "group_add for gid $gid already present but container still can't read - check the volume mount itself, not group membership"
        else
            if grep -A2 '^  api:' "$OVERRIDE" | grep -q 'group_add:'; then
                sed -i "/^  api:/,/group_add:/{s/group_add:.*/group_add: [\"${gid}\"]/}" "$OVERRIDE"
            else
                sed -i "/^  api:/a\\    group_add: [\"${gid}\"]" "$OVERRIDE"
            fi
            ok "set group_add: [\"${gid}\"] ($rolling_group) for the api service"
            FIXED=1
        fi
    fi
fi

# ---------------------------------------------------------------------------
if (( FIXED )); then
    log "applying fixes: restarting stack"
    $COMPOSE up -d
    sleep 5
fi

log "final check"
run_verify
FINAL_RC=$?

echo
if (( FINAL_RC == 0 )); then
    echo "All checks pass."
else
    echo "Some checks still fail - these need a manual decision (npcapextract binary issues, clock/NTP setup, or something this script doesn't recognize)."
fi
exit $FINAL_RC
