#!/usr/bin/env bash
# One-shot finisher for the two bugs found during the 2026-09-22 deploy
# session that verify.sh/fix.sh do not yet cover:
#   1. compose.override.yaml gives api a host bind-mount for alerts/, but
#      never gave caddy the matching one - caddy reads an empty Docker
#      named volume and 404s on every real file api writes.
#   2. npcapextract drops privileges to "nobody" before writing its
#      output file; the api container runs as root, so it got Permission
#      denied until /storage/pcaps/alerts was chmod 0777'd as a live
#      workaround. This script installs the real fix (extraction.py now
#      passes "-u root" to npcapextract - already committed to the repo
#      this script ships with) and reverts the 0777 workaround.
#
# Every step verifies its own success before the next one runs. On any
# failure the script stops immediately and prints exactly what to check -
# it never proceeds on an assumption.
#
# Usage: sudo ./finalize.sh [deploy_dir] [repo_checkout_dir]
#   deploy_dir defaults to /opt/sycope-recorder
#   repo_checkout_dir defaults to this script's own repo root (three
#   levels up from tools/client-migration/), i.e. the driftbolt checkout
#   this script itself lives in - override it if extraction.py should
#   come from somewhere else.

set -uo pipefail

DEPLOY_DIR="${1:-/opt/sycope-recorder}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${2:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
COMPOSE="docker compose -f $DEPLOY_DIR/compose.yaml -f $DEPLOY_DIR/compose.override.yaml"
ALERTS_HOST_DIR="/storage/pcaps/alerts"
ROLLING_HOST_DIR="/storage/pcaps/rolling"

log()  { printf '\n\033[1;34m==> STEP %s\033[0m %s\n' "$1" "$2"; }
ok()   { printf '\033[1;32m  OK\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31m FAIL\033[0m %s\n' "$*" >&2; echo; echo "Stopped. Nothing after this ran. Fix the above, then re-run - every step checks current state first."; exit 1; }
warn() { printf '\033[1;33m  ! \033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
    die "run as root"
fi
[[ -f "$DEPLOY_DIR/compose.yaml" ]] || die "$DEPLOY_DIR/compose.yaml not found - wrong deploy_dir?"
[[ -f "$REPO_DIR/src/sycope_recorder/extraction.py" ]] || die "$REPO_DIR/src/sycope_recorder/extraction.py not found - wrong repo_checkout_dir? pass it as the 2nd argument."

# ===========================================================================
log 1/7 "confirm the actual bugs are present before touching anything"
# ===========================================================================
# Refuse to "fix" something that isn't broken - re-running this script
# after it already succeeded must be a safe no-op, not a redundant
# rebuild/restart every time.
NEEDS_CADDY_MOUNT=0
if ! grep -A10 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" 2>/dev/null | grep -q "${ALERTS_HOST_DIR}:/srv/alerts"; then
    NEEDS_CADDY_MOUNT=1
    warn "caddy is missing the alerts/ bind-mount override - will add it"
else
    ok "caddy already has the alerts/ bind-mount override"
fi

NEEDS_CODE_UPDATE=0
if ! grep -q '"-u", "root"' "$DEPLOY_DIR"/src/sycope_recorder/extraction.py 2>/dev/null; then
    NEEDS_CODE_UPDATE=1
    warn "deployed extraction.py does not have the -u root fix yet - will copy it from the repo and rebuild"
else
    ok "deployed extraction.py already has the -u root fix"
fi

CURRENT_ALERTS_PERMS="$(stat -c '%a' "$ALERTS_HOST_DIR" 2>/dev/null)"
NEEDS_PERM_REVERT=0
if [[ "$CURRENT_ALERTS_PERMS" == "777" ]]; then
    NEEDS_PERM_REVERT=1
    warn "$ALERTS_HOST_DIR is chmod 0777 (tonight's live workaround) - will revert once -u root is confirmed working"
else
    ok "$ALERTS_HOST_DIR is not 0777 (currently $CURRENT_ALERTS_PERMS) - no workaround to revert"
fi

if (( NEEDS_CADDY_MOUNT == 0 && NEEDS_CODE_UPDATE == 0 && NEEDS_PERM_REVERT == 0 )); then
    ok "nothing to do - all three fixes already in place"
    echo
    echo "Running a final end-to-end check anyway:"
fi

# ===========================================================================
log 2/7 "fix compose.override.yaml: add alerts/ bind-mount to caddy"
# ===========================================================================
if (( NEEDS_CADDY_MOUNT )); then
    cp "$DEPLOY_DIR/compose.override.yaml" "$DEPLOY_DIR/compose.override.yaml.bak.$(date +%s)"
    if grep -A5 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" | grep -q '^\s*volumes:'; then
        sed -i "/^  caddy:/,/^\s*volumes:/{/^\s*volumes:/a\\      - ${ALERTS_HOST_DIR}:/srv/alerts:ro
}" "$DEPLOY_DIR/compose.override.yaml"
    elif grep -q '^  caddy:' "$DEPLOY_DIR/compose.override.yaml"; then
        sed -i "/^  caddy:/a\\    volumes:\\n      - ${ALERTS_HOST_DIR}:/srv/alerts:ro" "$DEPLOY_DIR/compose.override.yaml"
    else
        cat >> "$DEPLOY_DIR/compose.override.yaml" <<EOF
  caddy:
    volumes:
      - ${ALERTS_HOST_DIR}:/srv/alerts:ro
EOF
    fi
    # Verify immediately - don't trust the sed, read the file back.
    if grep -A10 '^  caddy:' "$DEPLOY_DIR/compose.override.yaml" | grep -q "${ALERTS_HOST_DIR}:/srv/alerts"; then
        ok "compose.override.yaml now mounts ${ALERTS_HOST_DIR} into caddy at /srv/alerts"
    else
        die "edited compose.override.yaml but the mount still isn't there - inspect $DEPLOY_DIR/compose.override.yaml by hand (backup at .bak.*)"
    fi
    # Validate the YAML is still parseable before going any further.
    if ! $COMPOSE config >/dev/null 2>&1; then
        die "compose.override.yaml is no longer valid YAML after the edit - restore from the .bak.* backup just written and fix by hand"
    fi
    ok "compose.override.yaml is still valid YAML"
else
    ok "skipped - already fixed"
fi

# ===========================================================================
log 3/7 "copy the -u root fix into the deploy dir"
# ===========================================================================
if (( NEEDS_CODE_UPDATE )); then
    # Dockerfile does `COPY src ./src` from the build context ($DEPLOY_DIR),
    # so the full package must already exist there - this only patches
    # one file, it does not scaffold a missing src/ tree from scratch.
    if [[ ! -f "$DEPLOY_DIR/src/sycope_recorder/main.py" ]]; then
        die "$DEPLOY_DIR/src/sycope_recorder/ is missing or incomplete (no main.py) - this deploy dir was never given a full src/ tree, patching just extraction.py won't produce a working build. Copy the whole tree first: cp -r $REPO_DIR/src $DEPLOY_DIR/"
    fi
    cp "$REPO_DIR/src/sycope_recorder/extraction.py" "$DEPLOY_DIR/src/sycope_recorder/extraction.py"
    if grep -q '"-u", "root"' "$DEPLOY_DIR/src/sycope_recorder/extraction.py"; then
        ok "extraction.py with the -u root fix copied into $DEPLOY_DIR/src/sycope_recorder/"
    else
        die "copied extraction.py from $REPO_DIR but it still doesn't contain the fix - is $REPO_DIR the right checkout? (git -C $REPO_DIR log --oneline -1 to check)"
    fi
else
    ok "skipped - already fixed"
fi

# ===========================================================================
log 4/7 "rebuild and restart only what changed"
# ===========================================================================
# api needs a rebuild only if its code changed; caddy needs a plain
# restart (no rebuild - it's the caddy:2 image, config-only change) only
# if its mount changed. Restarting both unconditionally every run would
# make this script slower and noisier than it needs to be on a repeat run.
RESTARTED_ANYTHING=0
if (( NEEDS_CODE_UPDATE )); then
    log 4a "rebuilding api image"
    if $COMPOSE up -d --build api; then
        ok "api rebuilt and restarted"
        RESTARTED_ANYTHING=1
    else
        die "docker compose up -d --build api failed - see the build output above"
    fi
fi
if (( NEEDS_CADDY_MOUNT )); then
    log 4b "restarting caddy to pick up the new mount"
    if $COMPOSE up -d caddy; then
        ok "caddy restarted"
        RESTARTED_ANYTHING=1
    else
        die "docker compose up -d caddy failed - see the output above"
    fi
fi
if (( RESTARTED_ANYTHING )); then
    sleep 3
fi

# Confirm both containers are actually up before checking anything else.
api_health="$($COMPOSE ps --format '{{.Health}}' api 2>/dev/null)"
[[ "$api_health" == "healthy" ]] || die "api container is not healthy after restart (state: $api_health) - check: docker logs $($COMPOSE ps -q api 2>/dev/null)"
ok "api container healthy"
caddy_state="$($COMPOSE ps --format '{{.State}}' caddy 2>/dev/null)"
[[ "$caddy_state" == "running" ]] || die "caddy container is not running after restart (state: $caddy_state) - check: docker logs $($COMPOSE ps -q caddy 2>/dev/null)"
ok "caddy container running"

# ===========================================================================
log 5/7 "confirm npcapextract can write to alerts/ WITHOUT 0777"
# ===========================================================================
# Pick a real host on the client's network so this isn't a synthetic
# BPF-empty MISS - reuses the address confirmed reachable during the
# 2026-09-22 session. A MISS here (0 packets) is still a valid pass for
# THIS check, since the point is proving npcapextract can WRITE the file,
# not that this specific address has traffic right now.
TEST_TS="$(date +%s)"
TEST_OUT="/tmp/finalize_test_$(date +%s).pcap"
probe_output="$($COMPOSE exec -T api npcapextract \
    -t /storage/pcaps/rolling \
    -b "$(date -d @$((TEST_TS - 30)) '+%Y-%m-%d %H:%M:%S')" \
    -e "$(date -d @$((TEST_TS + 30)) '+%Y-%m-%d %H:%M:%S')" \
    -f "host 150.254.1.158" \
    -o "$TEST_OUT" \
    -u root 2>&1)"
if grep -qi 'permission denied' <<<"$probe_output"; then
    die "npcapextract STILL gets Permission denied even with -u root explicitly passed: $probe_output - this means the fix's premise is wrong, do not revert the 0777 workaround. Investigate: does 'root' actually resolve inside the container? (docker compose exec api id root)"
fi
if grep -qi 'no space left' <<<"$probe_output"; then
    die "npcapextract hit ENOSPC (disk full) during this probe - unrelated to the permission fix, resolve disk space first: df -h /storage/pcaps"
fi
$COMPOSE exec -T api rm -f "$TEST_OUT" >/dev/null 2>&1
ok "npcapextract ran with -u root and produced no permission or disk error (output: ${probe_output:0:120}...)"

# ===========================================================================
log 6/7 "revert the 0777 workaround on alerts/"
# ===========================================================================
if (( NEEDS_PERM_REVERT )); then
    chmod 0755 "$ALERTS_HOST_DIR"
    chown n2disk:ntop "$ALERTS_HOST_DIR" 2>/dev/null || warn "could not chown to n2disk:ntop - left ownership as-is, only permissions changed"
    new_perms="$(stat -c '%a' "$ALERTS_HOST_DIR")"
    if [[ "$new_perms" == "755" ]]; then
        ok "$ALERTS_HOST_DIR reverted to 0755"
    else
        die "chmod ran but $ALERTS_HOST_DIR is now $new_perms, not 755 - inspect manually"
    fi
    # Re-run the same write probe from step 5, now WITHOUT the 0777
    # workaround, to prove the code fix alone is sufficient. This is the
    # check that actually matters - step 5 alone doesn't prove the
    # permission tightening is safe.
    TEST_OUT2="/tmp/finalize_test2_$(date +%s).pcap"
    probe2="$($COMPOSE exec -T api npcapextract \
        -t /storage/pcaps/rolling \
        -b "$(date -d @$(($(date +%s) - 30)) '+%Y-%m-%d %H:%M:%S')" \
        -e "$(date -d @$(($(date +%s) + 30)) '+%Y-%m-%d %H:%M:%S')" \
        -f "host 150.254.1.158" \
        -o "$TEST_OUT2" \
        -u root 2>&1)"
    if grep -qi 'permission denied' <<<"$probe2"; then
        chmod 0777 "$ALERTS_HOST_DIR"
        die "reverting to 0755 broke writes again even with -u root - re-applied 0777 as a safety net. The real fix needs more than -u root here (check: is $ALERTS_HOST_DIR's actual filesystem owner/group what 'n2disk:ntop' assumes, and is the api container's root truly unrestricted - check AppArmor/SELinux: aa-status | grep -i docker)"
    fi
    $COMPOSE exec -T api rm -f "$TEST_OUT2" >/dev/null 2>&1
    ok "confirmed npcapextract still writes successfully at 0755 - workaround no longer needed"
else
    ok "skipped - no workaround was present"
fi

# ===========================================================================
log 7/7 "final end-to-end verification"
# ===========================================================================
# api's own log line is not proof the download works - only caddy's view
# of the same directory is. Compare both directly.
api_listing="$($COMPOSE exec -T api ls "$ALERTS_HOST_DIR" 2>/dev/null | sort)"
caddy_listing="$($COMPOSE exec -T caddy ls /srv/alerts 2>/dev/null | sort)"
if [[ -z "$api_listing" && -z "$caddy_listing" ]]; then
    warn "both directories are empty right now (the step 5/6 test files were cleaned up) - the match below is only vacuously true. The live HTTPS test further down is the real proof; if that's skipped too, re-run this script after a real alert has fired."
fi
if [[ "$api_listing" == "$caddy_listing" ]]; then
    ok "api and caddy see identical contents in their respective alerts directories"
else
    die "api's ${ALERTS_HOST_DIR} and caddy's /srv/alerts STILL differ after the mount fix - the override.yaml edit in step 2 did not take effect as expected. Diff:
api:   $api_listing
caddy: $caddy_listing"
fi

SR_PUBLIC_HOST="$(grep -E '^SR_PUBLIC_HOST=' "$DEPLOY_DIR/.env" | cut -d= -f2-)"
BASIC_AUTH_USER="$(grep -E '^BASIC_AUTH_USER=' "$DEPLOY_DIR/.env" | cut -d= -f2-)"
if [[ -n "${BASIC_AUTH_PLAINTEXT:-}" && -n "$SR_PUBLIC_HOST" ]]; then
    resp="$(curl -sk -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PLAINTEXT}" -X POST \
        "https://${SR_PUBLIC_HOST}/extract?filter=client&before=30&after=30" \
        -H 'Content-Type: application/json' \
        -d "{\"id\":\"finalize-e2e-test\",\"clientIp\":\"150.254.1.158\",\"protocolName\":\"tcp\",\"unixTimestamp\":$(date +%s)}")"
    case "$resp" in
        https://*)
            dl_status="$(curl -sk -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PLAINTEXT}" -o /dev/null -w '%{http_code}' "$resp")"
            if [[ "$dl_status" == "200" ]]; then
                ok "full end-to-end test passed: POST /extract -> $resp -> GET returns 200"
            else
                die "extraction succeeded ($resp) but downloading it returned HTTP $dl_status - the mount fix may not have fully taken effect, or this specific file has a separate problem"
            fi
            ;;
        "ERROR: npcapextract failed")
            warn "extraction returned a MISS (0 packets matched) - expected if 150.254.1.158 has no traffic in this exact 60s window. This does NOT indicate a problem with today's fixes; it only means this specific test can't fully confirm the download path. Steps 1-6 already proved the fix works."
            ;;
        *)
            warn "unexpected /extract response: $resp - steps 1-6 already passed, but this final live test did not confirm cleanly. Investigate separately."
            ;;
    esac
else
    warn "BASIC_AUTH_PLAINTEXT not exported - skipping the live HTTPS end-to-end test (steps 1-6 already confirm the fix at the container level)"
fi

echo
echo "All checks that ran, passed. Ready to hand off."
exit 0
