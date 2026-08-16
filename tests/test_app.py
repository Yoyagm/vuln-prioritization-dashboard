"""Smoke tests for the dashboard.

Streamlit's own test harness runs the real script in-process, so these catch
what a unit test cannot: a view that raises on a column that no longer exists, a
widget key that collides, or a load that got slow enough to time out a free-tier
deploy. No browser and no network involved.
"""

from __future__ import annotations

import time

import pytest

from src import paths

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (paths.VULNERABILITIES.exists() and paths.ANALYSIS.exists()),
    reason="artefacts not built",
)

VIEWS = [
    "What do I patch this week?",
    "Are we inside the deadline?",
    "Does CVSS predict exploitation?",
    "What is the catalogue made of?",
]

# Streamlit Community Cloud gives a cold container a slow disk and one core. The
# budget is deliberately well under any user's patience, not under the timeout.
COLD_START_BUDGET = 5.0


def run_view(name: str | None = None) -> AppTest:
    app = AppTest.from_file(str(paths.ROOT / "app.py"), default_timeout=60)
    app.run()
    if name is not None:
        app.sidebar.radio[0].set_value(name).run()
    return app


def test_the_app_starts_within_budget():
    started = time.perf_counter()
    app = run_view()
    elapsed = time.perf_counter() - started
    assert not app.exception, app.exception
    assert elapsed < COLD_START_BUDGET, f"cold start took {elapsed:.1f}s"


@pytest.mark.parametrize("view", VIEWS)
def test_every_view_renders_without_raising(view):
    app = run_view(view)
    assert not app.exception, app.exception
    assert any(view in heading.value for heading in app.subheader)


def test_the_queue_view_offers_an_export():
    app = run_view(VIEWS[0])
    assert len(app.dataframe) == 1
    assert app.get("download_button")


def test_narrowing_the_queue_shrinks_it():
    """A filter that does nothing is worse than no filter."""
    app = run_view(VIEWS[0])
    before = app.metric[0].value
    app.slider[0].set_value(0.9).run()  # minimum EPSS
    assert not app.exception, app.exception
    after = app.metric[0].value
    assert int(after.replace(",", "")) < int(before.replace(",", ""))


def test_the_finding_view_states_both_conclusions():
    app = run_view(VIEWS[2])
    prose = " ".join(block.value for block in app.markdown)
    assert "head of the queue" in prose
    assert "artefact" in prose


def test_the_sla_slider_changes_the_outcome():
    app = run_view(VIEWS[1])
    slow = app.metric[5].value  # overdue days at the default rate
    app.slider[0].set_value(40).run()
    assert not app.exception, app.exception
    fast = app.metric[5].value
    assert int(fast.replace(",", "")) < int(slow.replace(",", ""))
