"""Acceptance tests for the published numbers.

These assert against the committed ``analysis.json``: the file the README quotes
and the dashboard draws. Two kinds of check live here.

The first pins the headline figures to the values recorded in the spec, within
1 %. Feeds move -- KEV grows weekly -- so a small drift is expected and a large
one means something changed that a human should look at before publishing.

The second pins the *claims* rather than the numbers: EPSS wins at the head of
the queue at every cutoff, and loses on total effort at every cutoff. Those two
sentences are the project's argument. If a data refresh ever breaks them, the
README stops being true, and this is where that gets caught.
"""

from __future__ import annotations

import json

import pytest

from src import analyse, paths

# Recorded in docs/specs/vuln-prioritization-dashboard.md §1 on 2026-08-15.
SPEC_RETROSPECTIVE = {"cvss": 137_952, "epss": 22_736}
SPEC_BUDGET_COVERAGE = {"cvss": 0.354, "epss": 0.888}
SPEC_PROSPECTIVE = {
    "2023-08-15": {"positives": 143, "cvss": 0.36, "epss": 0.52},
    "2024-02-15": {"positives": 133, "cvss": 0.33, "epss": 0.50},
    "2024-08-15": {"positives": 139, "cvss": 0.36, "epss": 0.43},
    "2025-02-15": {"positives": 112, "cvss": 0.29, "epss": 0.37},
    "2025-08-15": {"positives": 86, "cvss": 0.30, "epss": 0.55},
}

pytestmark = pytest.mark.skipif(
    not paths.ANALYSIS.exists(), reason="analysis.json not built"
)


@pytest.fixture(scope="module")
def analysis() -> dict:
    return json.loads(paths.ANALYSIS.read_text())


def test_effort_to_cover_eighty_percent_matches_the_spec(analysis):
    strategies = analysis["retrospective"]["strategies"]
    for name, expected in SPEC_RETROSPECTIVE.items():
        actual = strategies[name]["effort_at"]["0.8"]
        assert actual == pytest.approx(expected, rel=0.01), name


def test_equal_budget_coverage_matches_the_spec(analysis):
    strategies = analysis["retrospective"]["strategies"]
    for name, expected in SPEC_BUDGET_COVERAGE.items():
        assert strategies[name]["coverage_at_budget"] == pytest.approx(expected, abs=0.01)


def test_every_cutoff_is_present_and_matches_the_spec(analysis):
    blocks = {block["cutoff"]: block for block in analysis["prospective"]}
    assert set(blocks) == set(SPEC_PROSPECTIVE)
    for cutoff, expected in SPEC_PROSPECTIVE.items():
        block = blocks[cutoff]
        assert block["positives"] == pytest.approx(expected["positives"], rel=0.05), cutoff
        for name in ("cvss", "epss"):
            actual = block["strategies"][name]["coverage_at_budget"]
            assert actual == pytest.approx(expected[name], abs=0.02), f"{cutoff} {name}"


def test_epss_wins_at_the_head_of_the_queue_everywhere(analysis):
    """Claim one of the README."""
    for block in analysis["prospective"]:
        cvss = block["strategies"]["cvss"]["coverage_at_budget"]
        epss = block["strategies"]["epss"]["coverage_at_budget"]
        assert epss > cvss, f"{block['cutoff']}: EPSS {epss:.2f} did not beat CVSS {cvss:.2f}"


def test_epss_loses_on_total_effort_everywhere(analysis):
    """Claim two, the counter-intuitive one, and the reason the project exists."""
    for block in analysis["prospective"]:
        ratio = block["effort_ratio"]["0.8"]
        assert ratio < 1.0, (
            f"{block['cutoff']}: EPSS needed less work than CVSS to reach 80% "
            f"(ratio {ratio:.2f}) -- the README's second claim no longer holds"
        )


def test_the_retrospective_gap_is_much_larger_than_the_prospective_one(analysis):
    """The whole argument: the quoted advantage shrinks when scores are frozen."""
    retro = analysis["retrospective"]["strategies"]
    retro_ratio = retro["cvss"]["effort_at"]["0.8"] / retro["epss"]["effort_at"]["0.8"]
    worst_prospective = max(block["effort_ratio"]["0.8"] for block in analysis["prospective"])
    assert retro_ratio > 4.0
    assert worst_prospective < 1.0


def test_both_strategies_beat_random(analysis):
    strategies = analysis["retrospective"]["strategies"]
    for name in ("cvss", "epss"):
        assert (
            strategies[name]["effort_at"]["0.8"] < strategies["random"]["effort_at"]["0.8"]
        ), name


def test_confidence_intervals_are_reported_and_bracket_the_estimate(analysis):
    for block in analysis["prospective"]:
        for name in ("cvss", "epss"):
            strategy = block["strategies"][name]
            low, high = strategy["coverage_ci95"]
            assert low <= strategy["coverage_at_budget"] <= high
            assert 0.0 <= low < high <= 1.0


def test_curves_are_thinned_and_the_file_stays_small(analysis):
    for block in analysis["retrospective"]["strategies"].values():
        assert len(block["curve"]) <= 500
    assert paths.ANALYSIS.stat().st_size / 1e6 <= 2.0


def test_provenance_is_recorded(analysis):
    assert analysis["kev_catalog_version"]
    assert analysis["epss_score_date"]
    assert "neither endorsed nor certified" in analysis["nvd_notice"]


def test_sla_windows_are_plausible(analysis):
    sla = analysis["sla"]
    assert sla["count"] > 1_000
    assert 0 < sla["ransomware"] < sla["count"]
    assert 0 < sla["window_days"]["median"] <= 365
    assert sla["window_days"]["min"] >= 0


def test_sla_is_computed_from_the_kev_rows_only(joined):
    """Unit check on the fixture, independent of the committed artefact."""
    summary = analyse.sla(joined)
    assert summary["count"] == int(joined["in_kev"].sum())
    assert summary["ransomware"] == int(joined["kev_ransomware"].sum())
