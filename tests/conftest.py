"""Shared fixtures, and the rule that no test may touch the network.

A test that reaches a feed is not testing this code, it is testing CISA's
uptime -- and it will fail on a plane, in CI, and on the day the URL moves.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly on any attempt to open a socket."""

    def refuse(*args, **kwargs):
        raise RuntimeError("tests must not use the network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(scope="session")
def nvd_dir() -> Path:
    return FIXTURES / "nvd"


@pytest.fixture(scope="session")
def kev_path() -> Path:
    return FIXTURES / "kev.json"


@pytest.fixture(scope="session")
def epss_path() -> Path:
    return FIXTURES / "epss.csv.gz"


@pytest.fixture(scope="session")
def fixture_items(nvd_dir) -> list[dict]:
    import json
    import lzma

    with lzma.open(nvd_dir / "CVE-1999.json.xz", "rt") as handle:
        return json.load(handle)["cve_items"]


@pytest.fixture(scope="session")
def joined(nvd_dir, kev_path, epss_path):
    """The fixture feeds run through the real join."""
    from src import build

    return build.build(nvd_dir=nvd_dir, kev_path=kev_path, epss_path=epss_path)
