"""Builds the extraction filename/time-window and shells out to npcapextract.

This is the layer where alert data actually turns into a PCAP: it derives
the output filename and the [begin, end] extraction window from the alert
timestamp, invokes npcapextract as a subprocess with the BPF filter built
elsewhere (bpf.py), and classifies the outcome into one of four caller-facing
results (success URL, "no BPF filter", timeout, or failure). No packet
inspection happens here or anywhere in this codebase — npcapextract does
that; this module is orchestration around it.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from datetime import datetime, timedelta

from sycope_recorder.alert import ParsedAlert
from sycope_recorder.bpf import build_bpf_filter
from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")

TS_FMT = "%Y-%m-%d %H:%M:%S"
# Intentionally ASCII-only (unlike the legacy implementation, which used
# str.isalnum() and thus accepted Unicode letters/digits). Sycope alert IDs
# are always ASCII/numeric, so behavior is identical for real inputs; the
# stricter ASCII allowlist is also safer when the sanitized value is embedded
# in a filename/URL. Do not "fix" this back to Unicode.
_ID_ALLOWED = re.compile(r"[^A-Za-z0-9_-]")

NO_BPF = "NO BPF FILTER"
ERR_TIMEOUT = "ERROR: npcapextract timeout"
ERR_FAILED = "ERROR: npcapextract failed"


def sanitize_id(raw: object) -> str:
    """Strip to [A-Za-z0-9_-], cap at 64 chars; "alert" if that leaves nothing."""
    cleaned = _ID_ALLOWED.sub("", str(raw))[:64]
    return cleaned or "alert"


def compute_window(alert_time: datetime, before: int, after: int) -> tuple[str, str]:
    """Format the [alert_time - before, alert_time + after] extraction window as npcapextract's expected timestamp strings."""
    begin = (alert_time - timedelta(seconds=before)).strftime(TS_FMT)
    end = (alert_time + timedelta(seconds=after)).strftime(TS_FMT)
    return begin, end


def build_filename(alert_time: datetime, raw_id: object) -> str:
    """Build the output .pcap filename from the alert time and sanitized alert id."""
    return f"{alert_time:%Y%m%d_%H%M%S}_{sanitize_id(raw_id)}.pcap"


def run_extraction(
    parsed: ParsedAlert,
    mode: str,
    before: int,
    after: int,
    settings: Settings,
) -> str:
    """Run npcapextract for one alert and classify the outcome into a caller-facing string.

    Builds the BPF filter, time window, and output path, then shells out to
    npcapextract with a hard subprocess timeout. Four outcomes are possible:
    no BPF filter could be built (returns NO_BPF without ever invoking the
    subprocess); the subprocess times out (ERR_TIMEOUT); it succeeds and
    produces a non-empty output file (returns the download URL, built from
    settings.public_host/download_prefix since Caddy serves the file, not
    npcapextract's own path); or it fails. "Fails" also covers a real quirk:
    rc=0 with a zero-byte output file means the BPF matched no packets in
    the window (a MISS, logged distinctly, and the empty file is deleted),
    but that case is currently merged into the same ERR_FAILED string as a
    genuine npcapextract error — callers cannot distinguish "no packets
    matched" from "npcapextract broke" from the return value alone.
    """
    # Deliberately the host's local wall-clock time, not UTC: npcapextract
    # indexes n2disk's timeline against the recording host's system clock,
    # so the extraction window must be expressed in that same clock's time
    # to land in the right chunk. This only produces a correct window when
    # the alert's unix timestamp (already UTC-epoch, tz-independent) and
    # this host's local clock actually agree on wall time - i.e. the
    # recording host's timezone must match whatever the alert source
    # assumes "local" means. Get that wrong and the window silently shifts
    # by the timezone offset. Safest deployment: run the recording host's
    # system clock in UTC, which makes this line's "local" time equal to
    # the alert's UTC-epoch time with zero ambiguity.
    alert_time = datetime.fromtimestamp(parsed.timestamp).astimezone()

    bpf = build_bpf_filter(parsed, mode)
    if not bpf:
        log.info("NO BPF FILTER for alert id=%s", parsed.alert_id)
        return NO_BPF

    os.makedirs(settings.output_dir, exist_ok=True)
    filename = build_filename(alert_time, parsed.alert_id)
    output_path = os.path.join(settings.output_dir, filename)
    begin, end = compute_window(alert_time, before, after)

    cmd = [
        settings.npcapextract_path,
        "-t", settings.timeline_dir,
        "-b", begin,
        "-e", end,
        "-f", bpf,
        "-o", output_path,
        # npcapextract drops privileges to "nobody" before opening the
        # output file by default. The api container runs as root, so
        # without this it gets a silent Permission denied writing to
        # output_dir unless that directory is world-writable - stay as
        # root instead of dropping to a user the container's own
        # filesystem permissions were never set up for.
        "-u", "root",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.extract_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        log.error("npcapextract timeout after %ss (id=%s)",
                  settings.extract_timeout_seconds, parsed.alert_id)
        return ERR_TIMEOUT

    ok = (
        proc.returncode == 0
        and os.path.exists(output_path)
        and os.path.getsize(output_path) > 0
    )
    if ok:
        size = os.path.getsize(output_path)
        url = f"https://{settings.public_host}/{settings.download_prefix}/{filename}"
        log.info("SUCCESS: %s (%d bytes) URL: %s", output_path, size, url)
        return url

    # Zero-byte "MISS": rc 0 but nothing matched. Distinct log, merged response.
    if proc.returncode == 0 and os.path.exists(output_path):
        log.info("MISS: no packets matched (id=%s); removing %s",
                 parsed.alert_id, output_path)
        try:
            os.remove(output_path)
        except OSError:
            pass

    log.error("npcapextract failed rc=%s stdout=%r stderr=%r",
              proc.returncode, proc.stdout, proc.stderr)
    return ERR_FAILED
