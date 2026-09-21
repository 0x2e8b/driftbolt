import json
from pathlib import Path

from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings

STUB = str(Path(__file__).resolve().parents[1] / "stubs" / "npcapextract")


def client(tmp_path, **kw) -> TestClient:
    s = Settings(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
        npcapextract_path=STUB,
        extract_timeout_seconds=2,
        **kw,
    )
    return TestClient(create_app(s, start_retention=False))


ALERT = {
    "id": "alert_12345",
    "clientIp": "1.1.1.1",
    "serverIp": "2.2.2.2",
    "serverPort": 443,
    "protocol": "tcp",
    "unixTimestamp": 1_782_050_580,  # 2026-07-01 ~ local
}


def test_success_returns_200_url_and_x_result(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    r = client(tmp_path).post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 200
    assert r.text.startswith("https://rec.example.com/downloads/")
    assert r.text.endswith("_alert_12345.pcap")
    assert r.headers["X-Result"] == r.text


def test_any_post_path_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    r = client(tmp_path).post("/anything", content=json.dumps(ALERT))
    assert r.status_code == 200


def test_no_bpf_when_no_flow_fields(tmp_path):
    r = client(tmp_path).post("/extract", content=json.dumps({"id": "x"}))
    assert r.status_code == 200
    assert r.text == "NO BPF FILTER"


def test_miss_and_failure_report_error(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "miss")
    r = client(tmp_path).post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 200
    assert r.text == "ERROR: npcapextract failed"


def test_empty_body_400(tmp_path):
    r = client(tmp_path).post("/extract", content=b"")
    assert r.status_code == 400
    assert r.text == "Empty request body"


def test_invalid_json_400(tmp_path):
    r = client(tmp_path).post("/extract", content=b"{not json")
    assert r.status_code == 400
    assert r.text == "Invalid JSON"


def test_payload_too_large_413(tmp_path):
    big = b"x" * (2 * 1024 * 1024 + 1)
    r = client(tmp_path).post("/extract", content=big)
    assert r.status_code == 413
    assert r.text == "Payload too large"


def test_query_param_clamping(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    # invalid before/after fall back to defaults; huge values clamp to 86400
    r = client(tmp_path).post(
        "/extract?filter=bogus&before=notanint&after=999999", content=json.dumps(ALERT)
    )
    assert r.status_code == 200  # bogus filter -> default full; extraction still runs


def test_unhandled_exception_returns_500_without_detail(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("boom: secret internal detail")

    monkeypatch.setattr("sycope_recorder.api.run_extraction", _boom)
    r = client(tmp_path).post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 500
    assert r.text == "Internal error"
    assert "boom" not in r.text
    assert "secret" not in r.text


def test_concurrency_gate_returns_429(tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_MODE", "success")
    c = client(tmp_path)
    app = c.app
    app.state.active_extractions = app.state.settings.max_concurrent_extractions
    r = c.post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "5"
    assert r.text == "Too many concurrent extractions"


def test_parse_error_does_not_leak_concurrency_counter(tmp_path, monkeypatch):
    """Pins that the concurrency gate is acquired before parse_alert runs, so a
    parse failure must still decrement active_extractions via the finally block —
    otherwise repeated bad requests would wedge the gate for legitimate ones."""
    monkeypatch.setenv("STUB_MODE", "success")
    c = client(tmp_path)
    app = c.app
    limit = app.state.settings.max_concurrent_extractions
    # valid JSON but NOT a dict -> parse_alert raises -> 500, must NOT leak the counter
    for _ in range(limit + 2):
        r = c.post("/extract", content="5")
        assert r.status_code == 500
        assert r.text == "Internal error"
    assert app.state.active_extractions == 0
    # gate must not be wedged: a subsequent valid request still succeeds
    r = c.post("/extract", content=json.dumps(ALERT))
    assert r.status_code == 200
