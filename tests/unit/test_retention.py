import os
import time
from pathlib import Path

from sycope_recorder.retention import sweep_once


def make_pcap(d: Path, name: str, size: int, age_seconds: float, now: float) -> Path:
    p = d / name
    p.write_bytes(b"x" * size)
    mtime = now - age_seconds
    os.utime(p, (mtime, mtime))
    return p


def test_age_based_deletion(tmp_path):
    now = time.time()
    old = make_pcap(tmp_path, "old.pcap", 10, age_seconds=100_000, now=now)
    new = make_pcap(tmp_path, "new.pcap", 10, age_seconds=1, now=now)
    stats = sweep_once(str(tmp_path), max_age_seconds=3600, max_total_bytes=0, now=now)
    assert not old.exists()
    assert new.exists()
    assert stats["deleted"] == 1


def test_size_cap_deletes_oldest_first(tmp_path):
    now = time.time()
    a = make_pcap(tmp_path, "a.pcap", 100, age_seconds=300, now=now)
    b = make_pcap(tmp_path, "b.pcap", 100, age_seconds=200, now=now)
    c = make_pcap(tmp_path, "c.pcap", 100, age_seconds=100, now=now)
    # total = 300 bytes, cap = 150 -> must delete oldest (a) then next-oldest (b) to reach <=150
    sweep_once(str(tmp_path), max_age_seconds=0, max_total_bytes=150, now=now)
    assert not a.exists()
    assert not b.exists()
    assert c.exists()


def test_disabled_rules_delete_nothing(tmp_path):
    now = time.time()
    p = make_pcap(tmp_path, "keep.pcap", 10, age_seconds=999_999, now=now)
    stats = sweep_once(str(tmp_path), max_age_seconds=0, max_total_bytes=0, now=now)
    assert p.exists()
    assert stats["deleted"] == 0


def test_only_pcap_files_considered(tmp_path):
    now = time.time()
    other = tmp_path / "notes.txt"
    other.write_bytes(b"x" * 10)
    os.utime(other, (now - 999_999, now - 999_999))
    sweep_once(str(tmp_path), max_age_seconds=1, max_total_bytes=0, now=now)
    assert other.exists()


def test_missing_dir_is_safe(tmp_path):
    stats = sweep_once(str(tmp_path / "nope"), 1, 1, time.time())
    assert stats == {"deleted": 0, "bytes": 0}
