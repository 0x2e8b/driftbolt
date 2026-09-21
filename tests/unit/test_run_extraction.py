from datetime import datetime
from pathlib import Path


from sycope_recorder.alert import ParsedAlert
from sycope_recorder.config import Settings
from sycope_recorder.extraction import (
    ERR_FAILED,
    ERR_TIMEOUT,
    NO_BPF,
    run_extraction,
)

STUB = str(Path(__file__).resolve().parents[1] / "stubs" / "npcapextract")


def make_settings(tmp_path: Path, **kw) -> Settings:
    base = dict(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
        npcapextract_path=STUB,
        extract_timeout_seconds=2,
    )
    base.update(kw)
    return Settings(**base)


def full_alert(ts: float) -> ParsedAlert:
    return ParsedAlert(
        client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443,
        protocol="tcp", timestamp=ts, alert_id="alert_12345", alert_name="n",
    )


def test_success_returns_https_url(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    s = make_settings(tmp_path)
    ts = datetime(2026, 7, 1, 14, 3, 0).timestamp()
    result = run_extraction(full_alert(ts), "full", 360, 360, s)
    assert result == (
        "https://rec.example.com/downloads/20260701_140300_alert_12345.pcap"
    )
    assert (tmp_path / "alerts" / "20260701_140300_alert_12345.pcap").exists()


def test_no_bpf_returns_early_without_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "fail")  # would fail IF it ran
    s = make_settings(tmp_path)
    empty = ParsedAlert(None, None, None, None, 0.0, "id", "n")
    assert run_extraction(empty, "full", 1, 1, s) == NO_BPF


def test_miss_zero_byte_reports_failed_and_deletes_file(tmp_path, monkeypatch):
    """A genuine no-match (rc 0, zero-byte file) is reported to the caller as
    ERR_FAILED, identically to a real npcapextract failure — see extraction.py's
    MISS handling."""
    monkeypatch.setenv("STUB_MODE", "miss")
    s = make_settings(tmp_path)
    ts = datetime(2026, 7, 1, 14, 3, 0).timestamp()
    assert run_extraction(full_alert(ts), "full", 1, 1, s) == ERR_FAILED
    assert not (tmp_path / "alerts" / "20260701_140300_alert_12345.pcap").exists()


def test_nonzero_exit_reports_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "fail")
    s = make_settings(tmp_path)
    assert run_extraction(full_alert(0.0), "full", 1, 1, s) == ERR_FAILED


def test_timeout_reports_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "timeout")
    s = make_settings(tmp_path, extract_timeout_seconds=1)
    assert run_extraction(full_alert(0.0), "full", 1, 1, s) == ERR_TIMEOUT
