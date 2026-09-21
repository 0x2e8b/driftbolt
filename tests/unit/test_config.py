import pytest
from pydantic import ValidationError

from sycope_recorder.config import Settings, VALID_FILTER_MODES


def test_defaults_apply_when_only_required_present():
    s = Settings(public_host="rec.example.com")
    assert s.download_prefix == "downloads"
    assert s.default_before == 360
    assert s.default_after == 360
    assert s.extract_timeout_seconds == 300
    assert s.max_concurrent_extractions == 1


def test_public_host_is_required():
    with pytest.raises(ValidationError):
        Settings()  # no public_host, no env


def test_env_override(monkeypatch):
    monkeypatch.setenv("SR_PUBLIC_HOST", "host.local")
    monkeypatch.setenv("SR_DEFAULT_BEFORE", "10")
    s = Settings()
    assert s.public_host == "host.local"
    assert s.default_before == 10


def test_max_concurrent_clamped_to_one_minimum():
    assert Settings(public_host="h", max_concurrent_extractions=0).max_concurrent_extractions == 1
    assert Settings(public_host="h", max_concurrent_extractions=-5).max_concurrent_extractions == 1


def test_unknown_default_filter_falls_back_to_full():
    assert Settings(public_host="h", default_filter="bogus").default_filter == "full"
    assert "full" in VALID_FILTER_MODES
