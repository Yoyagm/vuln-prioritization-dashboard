"""How a prioritisation strategy is scored.

Everything in this module exists to answer one question: if you work down a
ranked list of vulnerabilities, how much of what actually gets exploited have
you covered by the time you have patched N of them?

The subtlety is ties. Tens of thousands of CVEs carry a CVSS base score of
exactly 9.8, so the order *inside* that block decides the answer -- and if you
let a sort settle it, what you have measured is the alphabetical order of CVE
identifiers. Every function here treats a tied block as its expected value under
uniformly random ordering within the block, which is the only reading that
describes a real defender rather than an artefact of pandas.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

MISSING = -1.0  # a score below every real one: absent data sorts last


def expected_curve(score: np.ndarray, label: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Coverage curve, expected over random tie-breaking.

    Returns ``(xs, ys)`` where ``ys[i]`` positives have been found after
    examining ``xs[i]`` items. Points land on block boundaries -- one block per
    distinct score -- and the curve is exactly linear in between, because within
    a block of ``n`` items holding ``p`` positives, taking ``k`` of them finds
    ``p * k / n`` in expectation. So :func:`numpy.interp` reads it without
    approximation.
    """
    if len(score) != len(label):
        raise ValueError("score and label must be the same length")
    order = np.argsort(-score, kind="stable")
    sorted_score, sorted_label = score[order], label[order]

    starts_block = np.empty(len(sorted_score), dtype=bool)
    starts_block[0] = True
    np.not_equal(sorted_score[1:], sorted_score[:-1], out=starts_block[1:])
    block_ends = np.flatnonzero(np.append(starts_block[1:], True)) + 1

    xs = np.concatenate(([0], block_ends)).astype(float)
    ys = np.concatenate(([0], np.cumsum(sorted_label)[block_ends - 1])).astype(float)
    return xs, ys


def effort_for(xs: np.ndarray, ys: np.ndarray, positives: float) -> float:
    """How many items must be examined to find ``positives`` of them."""
    return float(np.interp(positives, ys, xs))


def caught_at(xs: np.ndarray, ys: np.ndarray, budget: float) -> float:
    """How many positives sit inside the top ``budget`` items."""
    return float(np.interp(budget, xs, ys))


def average_ranks(score: np.ndarray) -> np.ndarray:
    """Rank descending with ties sharing their average position.

    A CVE in the middle of a 30,000-strong tie is neither first nor last in it;
    the average is where it sits in expectation.
    """
    return pd.Series(score).rank(ascending=False, method="average").to_numpy()


def bootstrap_coverage(
    ranks: np.ndarray,
    positive_index: np.ndarray,
    budget: float,
    *,
    resamples: int = 2000,
    seed: int = 20260815,
) -> tuple[float, float]:
    """95 % interval for the share of positives caught within ``budget``.

    Resampling is over the positives, not over the universe: there are 300,000
    CVEs but only 86 to 143 confirmed-exploited ones per cutoff, and that small
    number is where the uncertainty actually lives.
    """
    if len(positive_index) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    caught = ranks[positive_index] <= budget
    draws = rng.choice(caught, size=(resamples, len(positive_index)))
    shares = draws.mean(axis=1)
    low, high = np.percentile(shares, [2.5, 97.5])
    return float(low), float(high)


def decimate(xs: np.ndarray, ys: np.ndarray, max_points: int = 500) -> list[list[float]]:
    """Thin a curve for serialisation without moving it visibly.

    The raw curve has one point per distinct score, which is far more than any
    screen can show. Endpoints are always kept so the curve still starts at the
    origin and ends at full coverage.
    """
    if len(xs) <= max_points:
        keep = np.arange(len(xs))
    else:
        keep = np.unique(
            np.concatenate(
                [np.linspace(0, len(xs) - 1, max_points - 1).astype(int), [len(xs) - 1]]
            )
        )
    return [[round(float(xs[i]), 2), round(float(ys[i]), 4)] for i in keep]


def strategy_scores(frame: pd.DataFrame, column: str) -> np.ndarray:
    """A strategy's score vector, with absent scores sent to the back."""
    return frame[column].fillna(MISSING).to_numpy(dtype=float)
