from fastapi.testclient import TestClient

from sycope_recorder.api import create_app
from sycope_recorder.config import Settings


def test_retention_task_starts_and_stops(tmp_path):
    """Locks in the lifespan contract: shutdown must cancel the retention
    task cleanly rather than leaving it dangling (see create_app's lifespan)."""
    s = Settings(
        public_host="h",
        output_dir=str(tmp_path / "alerts"),
        retention_interval_seconds=3600,
    )
    app = create_app(s, start_retention=True)
    with TestClient(app) as c:  # triggers startup + shutdown
        assert c.get("/healthz").status_code == 200
        assert app.state.retention_task is not None
    # after context exit, task is cancelled/finished
    assert app.state.retention_task.done()
