"""Background sweep that deletes old/excess extracted PCAPs from output_dir.

The legacy system had no retention policy at all (SPEC.md §12 item 12,
§14) — extracted PCAPs would accumulate on disk indefinitely. This module
fills that gap with a periodic sweep, driven by retention_loop, that
enforces an age limit and a total-size cap independently. It has no
legacy-compatibility contract to honor since there was nothing before it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")


def _entries(output_dir: str) -> list[tuple[str, float, int]]:
    """List (path, mtime, size) for every .pcap file in output_dir, or empty if it's missing/unreadable."""
    result: list[tuple[str, float, int]] = []
    try:
        names = os.listdir(output_dir)
    except OSError:
        return result
    for name in names:
        if not name.endswith(".pcap"):
            continue
        path = os.path.join(output_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if os.path.isfile(path):
            result.append((path, st.st_mtime, st.st_size))
    return result


def _delete(path: str) -> int:
    """Delete path and return bytes freed; swallow OSError (e.g. already gone via a race) and return 0 instead of raising."""
    try:
        size = os.path.getsize(path)
        os.remove(path)
        return size
    except OSError as exc:
        log.warning("retention: could not delete %s: %s", path, exc)
        return 0


def sweep_once(
    output_dir: str, max_age_seconds: int, max_total_bytes: int, now: float
) -> dict:
    """Apply the age limit and the total-size cap as two independent passes, in that order.

    First, delete anything older than max_age_seconds (skipped entirely if
    max_age_seconds is 0). Then, among whatever survives that pass, delete
    oldest-first until the remaining total size is under max_total_bytes
    (skipped if max_total_bytes is 0). Running size-based cleanup only
    against the age pass's survivors means a file can be removed for being
    old, for being part of an oversized backlog, or both — never double
    counted. Either limit can be disabled independently by passing 0.
    """
    deleted = 0
    reclaimed = 0

    entries = _entries(output_dir)

    if max_age_seconds > 0:
        survivors = []
        for path, mtime, size in entries:
            if now - mtime > max_age_seconds:
                freed = _delete(path)
                if freed or not os.path.exists(path):
                    deleted += 1
                    reclaimed += freed
            else:
                survivors.append((path, mtime, size))
        entries = survivors

    if max_total_bytes > 0:
        total = sum(size for _, _, size in entries)
        for path, _mtime, size in sorted(entries, key=lambda e: e[1]):  # oldest first
            if total <= max_total_bytes:
                break
            freed = _delete(path)
            if freed or not os.path.exists(path):
                deleted += 1
                reclaimed += freed
                total -= size

    if deleted:
        log.info("retention: deleted %d file(s), reclaimed %d bytes", deleted, reclaimed)
    return {"deleted": deleted, "bytes": reclaimed}


async def retention_loop(settings: Settings, stop: asyncio.Event) -> None:
    """Run sweep_once on a timer until stop is set, started from api.py's lifespan.

    Each iteration's sweep is wrapped in try/except so a transient error
    (e.g. output_dir briefly missing) can't kill the background task —
    the loop just logs and tries again next interval. The "sleep" between
    iterations is asyncio.wait_for(stop.wait(), timeout=...) rather than
    asyncio.sleep(), so that when the app shuts down and lifespan sets
    stop and cancels the task, the wait returns immediately instead of
    blocking for up to a full retention_interval_seconds.
    """
    max_age = settings.retention_max_age_days * 86400
    while not stop.is_set():
        try:
            sweep_once(
                settings.output_dir,
                max_age,
                settings.retention_max_total_bytes,
                time.time(),
            )
        except Exception as exc:  # never let the sweep kill the loop
            log.warning("retention sweep error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.retention_interval_seconds)
        except asyncio.TimeoutError:
            continue
