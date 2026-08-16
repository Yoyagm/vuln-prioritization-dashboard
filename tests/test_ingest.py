"""Fetching, without fetching anything.

The watchdog is the reason this module exists, so it gets a test that actually
stalls a transfer. Everything is driven through a fake response: the autouse
network guard in conftest would refuse a real socket anyway.
"""

from __future__ import annotations

import json
import time

import pytest
import requests

from src import ingest


class FakeResponse:
    def __init__(self, chunks, *, status=200, delay=0.0):
        self._chunks = chunks
        self._status = status
        self._delay = delay

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self._status >= 400:
            error = requests.HTTPError(f"{self._status}")
            error.response = type("R", (), {"status_code": self._status})()
            raise error

    def iter_content(self, size):
        for chunk in self._chunks:
            if self._delay:
                time.sleep(self._delay)
            yield chunk


def serve(monkeypatch, *responses):
    """Answer successive requests with successive fakes, and count the calls."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return responses[min(len(calls) - 1, len(responses) - 1)]

    monkeypatch.setattr(ingest.requests, "get", fake_get)
    return calls


def test_download_writes_the_file_and_cleans_up(monkeypatch, tmp_path):
    serve(monkeypatch, FakeResponse([b"hello ", b"world"]))
    destination = tmp_path / "out.bin"
    written = ingest.download("https://example.invalid/f", destination)
    assert written == 11
    assert destination.read_bytes() == b"hello world"
    assert not list(tmp_path.glob("*.part"))


def test_a_dribbling_server_is_abandoned(monkeypatch, tmp_path):
    """The failure mode that cost 105 minutes: alive, but going nowhere.

    Bytes keep arriving, so a read timeout never fires. What must fire is the
    throughput check: nothing meaningful has arrived for too long.
    """
    monkeypatch.setattr(ingest, "STALL_SECONDS", 0.05)
    serve(monkeypatch, FakeResponse([b"x"] * 20, delay=0.03))
    with pytest.raises(RuntimeError, match="giving up"):
        ingest.download("https://example.invalid/slow", tmp_path / "out.bin", attempts=1)


def test_a_partial_file_never_replaces_a_good_one(monkeypatch, tmp_path):
    monkeypatch.setattr(ingest, "STALL_SECONDS", 0.05)
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"previous good copy")
    serve(monkeypatch, FakeResponse([b"x"] * 20, delay=0.03))
    with pytest.raises(RuntimeError):
        ingest.download("https://example.invalid/slow", destination, attempts=1)
    assert destination.read_bytes() == b"previous good copy"


def test_a_404_is_not_retried(monkeypatch, tmp_path):
    calls = serve(monkeypatch, FakeResponse([], status=404))
    with pytest.raises(requests.HTTPError):
        ingest.download("https://example.invalid/missing", tmp_path / "out.bin")
    assert len(calls) == 1, "a wrong URL does not get better by waiting"


def test_a_server_error_is_retried_then_succeeds(monkeypatch, tmp_path):
    monkeypatch.setattr(time, "sleep", lambda _: None)
    calls = serve(
        monkeypatch, FakeResponse([], status=503), FakeResponse([b"recovered"])
    )
    written = ingest.download("https://example.invalid/flaky", tmp_path / "out.bin")
    assert written == 9
    assert len(calls) == 2


def test_record_counts_come_from_the_real_fixture_shapes(kev_path, epss_path, nvd_dir):
    assert ingest.count_records(kev_path) == 5
    assert ingest.count_records(epss_path) == 11
    assert ingest.count_records(nvd_dir / "CVE-1999.json.xz") == 12


def test_unknown_shapes_return_none_rather_than_guessing(tmp_path):
    odd = tmp_path / "something.txt"
    odd.write_text("hello")
    assert ingest.count_records(odd) is None


def test_sha256_is_stable(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"abc")
    assert ingest.sha256(target) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_manifest_describes_what_is_on_disk(monkeypatch, tmp_path, kev_path):
    """A manifest entry must be able to prove which bytes produced the numbers."""
    from src import sources

    monkeypatch.setattr(ingest.paths, "ROOT", kev_path.parent)
    record = ingest.describe(sources.Source("kev", "https://example.invalid/kev", kev_path))
    payload = json.loads(kev_path.read_text())
    assert record.records == len(payload["vulnerabilities"])
    assert record.bytes == kev_path.stat().st_size
    assert len(record.sha256) == 64
    assert record.fetched_at.endswith("+00:00")
