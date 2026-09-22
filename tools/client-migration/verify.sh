#!/usr/bin/env bash
# Read-only diagnostic for a running sycope-recorder v2 deployment.
# Never modifies anything - safe to run any number of times, on a live
# system, without a maintenance window. Point of this script: everything
# it checks was something that actually went wrong during the 2026-09-22
# deployment session and cost time to diagnose live over a screen share.
#
# Usage: ./verify.sh [deploy_dir]
#   deploy_dir defaults to /opt/sycope-recorder

set -uo pipefail   # no -e: we want every check to run even if earlier ones fail

DEPLOY_DIR="${1:-/opt/sycope-recorder}"
COMPOSE="docker compose -f $DEPLOY_DIR/compose.yaml -f $DEPLOY_DIR/compose.override.yaml"

PASS=0
FAIL=0
WARN=0

ok()   { printf '\033[1;32m  OK  \033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m FAIL \033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '\033[1;33m WARN \033[0m %s\n' "$*"; WARN=$((WARN+1)); }
sec()  { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
sec "0. deploy dir sanity"
if [[ ! -d "$DEPLOY_DIR" ]]; then
    bad "$DEPLOY_DIR does not exist - wrong path? pass it as an argument"
    exit 1
fi
[[ -f "$DEPLOY_DIR/compose.yaml" ]] && ok "compose.yaml present" || bad "compose.yaml missing in $DEPLOY_DIR"
[[ -f "$DEPLOY_DIR/compose.override.yaml" ]] && ok "compose.override.yaml present" || bad "compose.override.yaml missing"
[[ -f "$DEPLOY_DIR/.env" ]] && ok ".env present" || bad ".env missing"

# ---------------------------------------------------------------------------
sec "1. containers up and healthy"
$COMPOSE ps --format '{{.Name}} {{.State}} {{.Health}}' 2>/dev/null | while read -r name state health; do
    if [[ "$state" == "running" ]]; then
        if [[ -z "$health" || "$health" == "healthy" ]]; then
            echo "  OK    $name: $state ${health:+($health)}"
        else
            echo "  WARN  $name: $state ($health)"
        fi
    else
        echo "  FAIL  $name: $state"
    fi
done
api_state="$($COMPOSE ps --format '{{.Health}}' api 2>/dev/null)"
[[ "$api_state" == "healthy" ]] && ok "api container healthy" || bad "api container not healthy ($api_state)"
caddy_running="$($COMPOSE ps --format '{{.State}}' caddy 2>/dev/null)"
[[ "$caddy_running" == "running" ]] && ok "caddy container running" || bad "caddy container not running ($caddy_running)"

# ---------------------------------------------------------------------------
sec "2. env file - basic auth hash sanity"
# Caddy AND docker compose both interpolate leading $ in values read from
# .env - a real bcrypt hash ($2a$14$...) gets silently mangled unless every
# $ is escaped as $$. This bit the deployment twice on 2026-09-22.
HASH_LINE="$(grep -E '^BASIC_AUTH_HASH=' "$DEPLOY_DIR/.env" 2>/dev/null | cut -d= -f2-)"
if [[ -z "$HASH_LINE" ]]; then
    bad "BASIC_AUTH_HASH not found in .env"
else
    dollar_count=$(grep -o '\$' <<<"$HASH_LINE" | wc -l)
    if (( dollar_count % 2 != 0 )); then
        bad "BASIC_AUTH_HASH has an odd number of \$ ($dollar_count) - looks unescaped, docker compose WILL mangle this. Every \$ must be \$\$."
    else
        ok "BASIC_AUTH_HASH has an even \$ count ($dollar_count) - looks escaped"
    fi
fi
# Cross-check what compose actually resolves it to at runtime (this is the
# only way to know for sure - compose does its own interpolation pass).
# `docker compose config` prints values AS WRITTEN in .env, i.e. still
# $$-escaped ($$2a$$14$$...) - it does not collapse $$ back to $ in its
# own output, even though that collapse does happen for real when the
# container actually starts. So the pattern here must match the escaped
# form, not a real bcrypt hash's single-$ form.
resolved_hash="$($COMPOSE config 2>/dev/null | grep -A2 'BASIC_AUTH_HASH' | grep -oE '\${2}2[aby]\${2}[0-9]+\${2}[A-Za-z0-9./]+' | head -1)"
if [[ -n "$resolved_hash" ]]; then
    ok "compose resolves a real-looking (escaped) bcrypt hash: ${resolved_hash:0:24}..."
else
    bad "compose config does not show a valid escaped bcrypt hash for BASIC_AUTH_HASH - it got mangled. Check for a leaked env-var-like fragment (e.g. \$KUNzNk) in caddy container warnings."
fi

# ---------------------------------------------------------------------------
sec "3. TLS certs"
CERT_DIR="$DEPLOY_DIR/certs"
if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]]; then
    ok "server.crt / server.key present on host at $CERT_DIR"
    expiry="$(openssl x509 -in "$CERT_DIR/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2)"
    [[ -n "$expiry" ]] && ok "cert expires: $expiry" || warn "could not read cert expiry"
else
    bad "$CERT_DIR/server.crt or server.key missing - Caddy will crash-loop with 'open /certs/server.crt: no such file or directory'"
fi
# Confirm the override actually mounts it into the caddy container - this
# is what got silently dropped on re-runs of the migration script, since
# the script always regenerates compose.override.yaml from scratch for the
# api service only.
if grep -A5 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" 2>/dev/null | grep -q '/certs:/certs'; then
    ok "compose.override.yaml mounts $CERT_DIR into the caddy container"
else
    bad "compose.override.yaml has NO certs bind-mount under the caddy service - re-add it manually, it does not survive a migrate-to-v2.sh re-run"
fi

# ---------------------------------------------------------------------------
sec "3b. alerts/ volume consistency between api and caddy"
# Root cause found on 2026-09-22: the base compose.yaml mounts a Docker
# NAMED VOLUME called "alerts" into both api (/storage/pcaps/alerts) and
# caddy (/srv/alerts:ro) - the same volume, so both containers see the
# same files by design. But compose.override.yaml's api section bind-
# mounts the HOST path /storage/pcaps/alerts over that same container
# path, which makes api write straight to the host filesystem instead of
# into the named volume. Caddy is never given the equivalent override, so
# it keeps reading the original (empty) named volume - it can never see
# any file api produces. api's own SUCCESS log with a real file size is
# not proof the download link works; only Caddy's own view of the
# directory is. A downloaded pcap returning 404 despite the file
# existing on the host almost certainly means this.
API_ALERTS_MOUNT="$(grep -B10 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" 2>/dev/null | grep -oE '/storage/pcaps/alerts:[^[:space:]]*' | head -1)"
CADDY_ALERTS_MOUNT="$(grep -A10 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" 2>/dev/null | grep -oE '/storage/pcaps/alerts:/srv/alerts[^[:space:]]*' | head -1)"
if [[ -n "$API_ALERTS_MOUNT" ]]; then
    # api has a host bind-mount override for alerts/ - caddy MUST have a
    # matching one, or it's reading a different, empty named volume.
    if [[ -n "$CADDY_ALERTS_MOUNT" ]]; then
        ok "both api and caddy bind-mount the same host path for alerts/ - downloads will match what api writes"
    else
        bad "api overrides alerts/ to a host bind-mount ($API_ALERTS_MOUNT) but caddy does NOT - caddy is still reading the original (likely empty) named volume and will 404 on every real file api produces. Add '- /storage/pcaps/alerts:/srv/alerts:ro' under the caddy service's volumes in compose.override.yaml."
    fi
else
    # Neither container has an override - both use the same named volume
    # from base compose.yaml, which is internally consistent (just not
    # a real host path you can inspect directly).
    ok "no alerts/ bind-mount override present - both containers share the same Docker named volume from compose.yaml (internally consistent)"
fi

# Belt-and-suspenders: actually compare what each container sees on disk,
# regardless of what the yaml says should be true.
if $COMPOSE ps --format '{{.Name}}' 2>/dev/null | grep -q caddy; then
    api_listing="$($COMPOSE exec -T api ls /storage/pcaps/alerts 2>/dev/null | sort)"
    caddy_listing="$($COMPOSE exec -T caddy ls /srv/alerts 2>/dev/null | sort)"
    if [[ -z "$api_listing" && -z "$caddy_listing" ]]; then
        warn "both api's /storage/pcaps/alerts and caddy's /srv/alerts are empty right now - can't confirm they match until at least one file exists"
    elif [[ "$api_listing" == "$caddy_listing" ]]; then
        ok "api and caddy see identical file listings in their respective alerts directories"
    else
        bad "api's /storage/pcaps/alerts and caddy's /srv/alerts have DIFFERENT contents right now - they are not the same underlying storage. Downloads will 404 for files api just wrote."
    fi
fi

# ---------------------------------------------------------------------------
sec "4. timezone consistency (host vs api container)"
HOST_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || echo unknown)"
HOST_EPOCH="$(date +%s)"
CONTAINER_EPOCH="$($COMPOSE exec -T api date +%s 2>/dev/null)"
CONTAINER_TZ="$($COMPOSE exec -T api date +%Z 2>/dev/null)"
echo "  host:      $HOST_TZ  ($(date '+%Y-%m-%d %H:%M:%S %Z'))"
if [[ -n "$CONTAINER_EPOCH" ]]; then
    echo "  container: $CONTAINER_TZ  ($($COMPOSE exec -T api date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null))"
    drift=$(( CONTAINER_EPOCH - HOST_EPOCH ))
    drift_abs=${drift#-}
    if (( drift_abs > 120 )); then
        bad "api container clock differs from host by ${drift}s - extraction windows will be off by roughly that amount"
    else
        ok "api container clock matches host within ${drift_abs}s"
    fi
else
    bad "could not read clock from api container - is it running?"
fi

# ---------------------------------------------------------------------------
sec "4b. capture interface link state"
# Confirmed root cause on 2026-09-22: n2disk logs a perfectly healthy
# startup (PF_RING attached, "packet capture started") and systemd shows
# it active, but the capture NIC itself had NO-CARRIER - a dead physical
# link (unplugged cable/SFP, or the far-end SPAN/TAP port down). n2disk
# has nothing to read from the wire and writes zero files, with no error
# that looks like a link problem anywhere in its own logs. This check
# would have caught it in seconds instead of a 30-minute chase through
# licensing logs, RX counters, and file timestamps.
# Read it straight from the running process's own command line - the
# only source that can't be stale or wrong, since it's what n2disk is
# actually using right now (config file conventions vary by install).
CAPTURE_IFACE="$(ps -eo args 2>/dev/null | grep '[n]2disk' | grep -oE '\-i\s+\S+' | awk '{print $2}' | head -1)"
if [[ -z "$CAPTURE_IFACE" ]]; then
    warn "could not auto-detect the capture interface name - pass it manually: ip -s link show <iface>"
else
    link_info="$(ip -s link show "$CAPTURE_IFACE" 2>&1)"
    if [[ -z "$link_info" ]]; then
        bad "interface $CAPTURE_IFACE not found - check the name is still correct"
    elif grep -q 'NO-CARRIER' <<<"$link_info"; then
        bad "$CAPTURE_IFACE has NO-CARRIER - dead physical link (cable/SFP unplugged, or the far-end SPAN/TAP port is down). n2disk will start cleanly and log nothing wrong, but capture zero packets. This is a physical-layer problem, not fixable from this host."
    else
        rx1="$(grep -A1 'RX:' <<<"$link_info" | tail -1 | awk '{print $2}')"
        sleep 2
        rx2="$(ip -s link show "$CAPTURE_IFACE" 2>/dev/null | grep -A1 'RX:' | tail -1 | awk '{print $2}')"
        if [[ -n "$rx1" && -n "$rx2" && "$rx2" -gt "$rx1" ]]; then
            ok "$CAPTURE_IFACE has carrier and RX bytes are increasing ($rx1 -> $rx2 over 2s) - live traffic confirmed"
        else
            warn "$CAPTURE_IFACE has carrier but RX bytes did not increase in 2s ($rx1 -> $rx2) - link is up but idle right now, or the counters are stale. Check again over a longer window before ruling out a traffic problem."
        fi
    fi
fi

# ---------------------------------------------------------------------------
sec "5. n2disk actually recording (not just installed)"
if systemctl is-active --quiet n2disk.service; then
    ok "n2disk.service is active"
else
    bad "n2disk.service is NOT active - nothing is being recorded right now"
fi
start_ts="$(systemctl show -p ActiveEnterTimestamp --value n2disk.service 2>/dev/null)"
[[ -n "$start_ts" && "$start_ts" != "n/a" ]] && echo "  n2disk started: $start_ts" || warn "no ActiveEnterTimestamp for n2disk.service"

ROLLING_DIR="/storage/pcaps/rolling"
if [[ -d "$ROLLING_DIR" ]]; then
    ok "$ROLLING_DIR exists"
    # This is the actual question that mattered on 2026-09-22: an old
    # directory tree existing is not evidence of live recording. Find the
    # single most-recently-modified file anywhere under it and check its age.
    newest="$(find "$ROLLING_DIR" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1)"
    if [[ -z "$newest" ]]; then
        bad "no files at all found under $ROLLING_DIR - n2disk has never written anything here, or is writing somewhere else"
    else
        newest_epoch="${newest%% *}"
        newest_path="${newest#* }"
        age_s=$(( $(date +%s) - ${newest_epoch%.*} ))
        age_min=$(( age_s / 60 ))
        echo "  newest file: $newest_path (${age_min} min old)"
        if (( age_min > 15 )); then
            bad "newest file under $ROLLING_DIR is ${age_min} minutes old - n2disk is not writing fresh data (check systemctl status n2disk.service and its own logs, not just 'is it active')"
        else
            ok "newest file under $ROLLING_DIR is ${age_min} minutes old - actively recording"
        fi
    fi
else
    bad "$ROLLING_DIR does not exist"
fi

# ---------------------------------------------------------------------------
sec "6. npcapextract reachable from inside the api container"
if $COMPOSE exec -T api test -x /usr/local/bin/npcapextract 2>/dev/null; then
    ok "npcapextract binary present and executable inside api container"
    if $COMPOSE exec -T api /usr/local/bin/npcapextract -h >/dev/null 2>&1; then
        ok "npcapextract runs inside the container (no missing shared libs)"
    else
        bad "npcapextract is present but fails to execute inside the container - likely missing shared libs in python:3.12-slim (ldd it on the host and compare)"
    fi
else
    bad "npcapextract not found/executable inside api container - check the bind mount and SR_NPCAPEXTRACT_PATH in compose.override.yaml"
fi

# ---------------------------------------------------------------------------
sec "6b. stuck npcapextract processes"
# extraction.py calls npcapextract via subprocess.run(timeout=...) - that
# timeout should always kill a hung process, but a process stuck in
# uninterruptible D-state (e.g. blocked on a stalled/unreadable mount)
# cannot be killed by SIGTERM/SIGKILL until the kernel unblocks it. With
# SR_MAX_CONCURRENT_EXTRACTIONS=1 (the default), a single stuck process
# silently blocks every subsequent extraction with no visible error on
# the Caddy/auth side - webhooks keep arriving (confirmed via tcpdump) but
# the api never responds in time, which is exactly what a client sees as
# a dead/timed-out destination. This is what we suspected caused webhooks
# to go quiet after 10:14 on 2026-09-22 without ever finding hard proof.
SR_EXTRACT_TIMEOUT_SECONDS="$(grep -E '^SR_EXTRACT_TIMEOUT_SECONDS=' "$DEPLOY_DIR/.env" 2>/dev/null | cut -d= -f2-)"
SR_EXTRACT_TIMEOUT_SECONDS="${SR_EXTRACT_TIMEOUT_SECONDS:-300}"
npcap_procs="$($COMPOSE exec -T api ps -eo pid,etimes,stat,comm 2>/dev/null | grep npcapextract | grep -v grep)"
if [[ -z "$npcap_procs" ]]; then
    ok "no npcapextract process currently running inside api container"
else
    echo "$npcap_procs" | while read -r pid etimes stat comm; do
        [[ -z "$pid" ]] && continue
        if (( etimes > SR_EXTRACT_TIMEOUT_SECONDS )); then
            echo "  FAIL  pid $pid ($comm) has run for ${etimes}s, past the ${SR_EXTRACT_TIMEOUT_SECONDS}s timeout - stuck, likely in state '$stat'"
        else
            echo "  WARN  pid $pid ($comm) running for ${etimes}s (under the ${SR_EXTRACT_TIMEOUT_SECONDS}s timeout, may be legitimate)"
        fi
    done
    max_etimes="$(echo "$npcap_procs" | awk '{print $2}' | sort -rn | head -1)"
    if [[ -n "$max_etimes" ]] && (( max_etimes > SR_EXTRACT_TIMEOUT_SECONDS )); then
        bad "npcapextract process stuck past its own timeout (${max_etimes}s > ${SR_EXTRACT_TIMEOUT_SECONDS}s) - with SR_MAX_CONCURRENT_EXTRACTIONS=1 this blocks every extraction behind it"
    else
        warn "npcapextract process(es) running but still within timeout - not necessarily a problem, re-check in a minute"
    fi
fi

# ---------------------------------------------------------------------------
sec "7. rolling/ directory permissions from inside the container"
if $COMPOSE exec -T api ls "$ROLLING_DIR" >/dev/null 2>&1; then
    ok "api container can list $ROLLING_DIR"
else
    bad "api container CANNOT read $ROLLING_DIR - check group_add in compose.override.yaml matches the host group owning rolling/ (stat -c '%G' $ROLLING_DIR)"
fi

# ---------------------------------------------------------------------------
sec "8. end-to-end HTTPS smoke test (no BPF-empty ambiguity)"
SR_PUBLIC_HOST="$(grep -E '^SR_PUBLIC_HOST=' "$DEPLOY_DIR/.env" 2>/dev/null | cut -d= -f2-)"
BASIC_AUTH_USER="$(grep -E '^BASIC_AUTH_USER=' "$DEPLOY_DIR/.env" 2>/dev/null | cut -d= -f2-)"
if [[ -z "$SR_PUBLIC_HOST" || -z "$BASIC_AUTH_USER" ]]; then
    warn "SR_PUBLIC_HOST or BASIC_AUTH_USER missing from .env - skipping HTTPS test"
elif [[ -z "${BASIC_AUTH_PLAINTEXT:-}" ]]; then
    warn "export BASIC_AUTH_PLAINTEXT=<password> before running this script to include the HTTPS smoke test"
else
    resp="$(curl -sk -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PLAINTEXT}" "https://${SR_PUBLIC_HOST}/healthz" 2>&1)"
    if grep -q '"status":"ok"' <<<"$resp"; then
        ok "GET /healthz over HTTPS with basic auth: $resp"
    elif grep -qi '401' <<<"$resp" || [[ -z "$resp" ]]; then
        bad "GET /healthz failed or empty response: '$resp' - check BASIC_AUTH_PLAINTEXT matches what's in .env, and check section 2/3 above"
    else
        warn "unexpected /healthz response: $resp"
    fi
fi

# ---------------------------------------------------------------------------
sec "summary"
echo "  PASS: $PASS   WARN: $WARN   FAIL: $FAIL"
if (( FAIL > 0 )); then
    echo
    echo "  Fix FAIL items top to bottom - later checks often fail as a side"
    echo "  effect of an earlier one (e.g. a mangled hash breaks both #2 and #8)."
    exit 1
fi
exit 0
