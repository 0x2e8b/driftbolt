from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings


def client(tmp_path) -> TestClient:
    s = Settings(
        public_host="rec.example.com",
        timeline_dir=str(tmp_path / "rolling"),
        output_dir=str(tmp_path / "alerts"),
    )
    return TestClient(create_app(s, start_retention=False))


def test_healthz_ok_no_auth(tmp_path):
    r = client(tmp_path).get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_help_endpoint_shape(tmp_path):
    r = client(tmp_path).get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert set(body["usage"]) == {"endpoint", "filter_modes", "defaults"}
    assert set(body["usage"]["filter_modes"]) == {"full", "hosts", "client", "server", "port"}
    assert body["usage"]["defaults"]["filter"] == "full"
    assert len(body["examples"]) == 3
