"""The load-bearing tests of the project.

If :func:`expected_curve` is wrong, every number in the README is wrong and
nothing else in the test suite would notice. So these tests use fixtures whose
right answer can be worked out by hand, and the tie-averaging guard carries a
negative control: a test that proves the guard fails when the behaviour it
guards is removed. A guard that cannot fail is not protecting anything.
"""

from __future__ import annotations

import numpy as np
import pytest

from src import metrics


def test_curve_is_exact_when_there_are_no_ties():
    # Scores all distinct, positives at ranks 1 and 3 of 4.
    score = np.array([9.0, 8.0, 7.0, 6.0])
    label = np.array([1.0, 0.0, 1.0, 0.0])
    xs, ys = metrics.expected_curve(score, label)
    assert list(xs) == [0, 1, 2, 3, 4]
    assert list(ys) == [0, 1, 1, 2, 2]


def test_ties_are_averaged_not_broken():
    """Ten CVEs share a score; two of them are exploited.

    Patching five of the ten finds one in expectation -- not two (the optimistic
    reading, if the exploited ones happen to sort first) and not zero (the
    pessimistic one). Any implementation that lets the sort decide gives one of
    the extremes, and which one depends on nothing but CVE numbering.
    """
    score = np.full(10, 9.8)
    label = np.array([0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0])
    xs, ys = metrics.expected_curve(score, label)

    assert metrics.caught_at(xs, ys, 5) == pytest.approx(1.0)
    assert metrics.caught_at(xs, ys, 10) == pytest.approx(2.0)
    # ...and the answer must not depend on where the positives sit in the block.
    shuffled = np.array([1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    xs2, ys2 = metrics.expected_curve(score, shuffled)
    assert metrics.caught_at(xs2, ys2, 5) == pytest.approx(1.0)


def test_tie_guard_would_catch_a_naive_sort():
    """Negative control for the test above.

    This is the implementation someone reaches for first: sort, then take a
    cumulative sum position by position. On the same fixture it reports two
    positives inside the first five items instead of one, so the assertion in
    :func:`test_ties_are_averaged_not_broken` really does fail when the
    averaging is removed -- which is what makes that test worth having.
    """
    score = np.full(10, 9.8)
    label = np.array([1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])

    naive_order = np.argsort(-score, kind="stable")
    naive_found = np.cumsum(label[naive_order])[4]

    xs, ys = metrics.expected_curve(score, label)
    assert naive_found == pytest.approx(2.0)
    assert metrics.caught_at(xs, ys, 5) == pytest.approx(1.0)
    assert naive_found != pytest.approx(metrics.caught_at(xs, ys, 5))


def test_missing_scores_sort_last():
    import pandas as pd

    frame = pd.DataFrame({"epss": [0.5, None, 0.9]})
    scores = metrics.strategy_scores(frame, "epss")
    assert scores[1] == metrics.MISSING
    assert scores[1] < scores.min(initial=np.inf, where=scores != metrics.MISSING)


def test_effort_and_caught_are_inverses():
    score = np.linspace(1.0, 0.0, 100)
    label = (np.arange(100) % 10 == 0).astype(float)
    xs, ys = metrics.expected_curve(score, label)
    effort = metrics.effort_for(xs, ys, 5)
    assert metrics.caught_at(xs, ys, effort) == pytest.approx(5.0)


def test_curve_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        metrics.expected_curve(np.zeros(3), np.zeros(4))


def test_bootstrap_interval_brackets_the_point_estimate():
    ranks = np.arange(1, 1001, dtype=float)
    positives = np.array([0, 1, 2, 500, 900])  # three of five inside a budget of 100
    low, high = metrics.bootstrap_coverage(ranks, positives, budget=100, resamples=500)
    assert 0.0 <= low <= 0.6 <= high <= 1.0


def test_bootstrap_is_reproducible():
    ranks = np.arange(1, 101, dtype=float)
    positives = np.array([0, 5, 50, 90])
    first = metrics.bootstrap_coverage(ranks, positives, budget=10)
    second = metrics.bootstrap_coverage(ranks, positives, budget=10)
    assert first == second


def test_bootstrap_with_no_positives_is_nan_not_a_crash():
    low, high = metrics.bootstrap_coverage(np.arange(10.0), np.array([], dtype=int), budget=5)
    assert np.isnan(low) and np.isnan(high)


def test_decimate_keeps_the_endpoints():
    xs = np.arange(5000, dtype=float)
    ys = xs / 2
    thinned = metrics.decimate(xs, ys, max_points=100)
    assert len(thinned) <= 100
    assert thinned[0] == [0.0, 0.0]
    assert thinned[-1] == [4999.0, 2499.5]


def test_average_ranks_share_positions_within_a_tie():
    ranks = metrics.average_ranks(np.array([9.8, 9.8, 5.0]))
    assert ranks[0] == ranks[1] == pytest.approx(1.5)
    assert ranks[2] == pytest.approx(3.0)
