from datetime import datetime

from sycope_recorder.extraction import build_filename, compute_window, sanitize_id


def test_sanitize_id_keeps_allowed_chars():
    assert sanitize_id("alert_12345") == "alert_12345"
    assert sanitize_id("a/b c!d-e_f") == "abcd-e_f"


def test_sanitize_id_truncates_to_64():
    assert sanitize_id("x" * 100) == "x" * 64


def test_sanitize_id_empty_fallback():
    assert sanitize_id("!!!") == "alert"


def test_sanitize_id_none_becomes_none_string():
    # str(None) == "None", which is all allowed chars -> "None"
    assert sanitize_id(None) == "None"


def test_compute_window():
    t = datetime(2026, 7, 1, 14, 3, 0)
    begin, end = compute_window(t, 360, 360)
    assert begin == "2026-07-01 13:57:00"
    assert end == "2026-07-01 14:09:00"


def test_build_filename():
    t = datetime(2026, 7, 1, 14, 3, 0)
    assert build_filename(t, "alert_12345") == "20260701_140300_alert_12345.pcap"
