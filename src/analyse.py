"""Produce every number the dashboard and the README display.

Nothing downstream recomputes a statistic and nothing is typed by hand into
prose: if a figure appears in the README it came out of ``analysis.json``, and a
test enforces that.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src import build, metrics, paths, sources

COVERAGE_POINTS = (0.5, 0.8, 0.9)

# The budget every strategy is held to: the size of the "patch everything rated
# critical" queue. It is not an arbitrary number, it is the policy most
# organisations actually run, which is what makes the comparison land.
CRITICAL = 9.0


def _curve_block(score: np.ndarray, label: np.ndarray, budget: float) -> dict[str, Any]:
    xs, ys = metrics.expected_curve(score, label)
    positives = float(label.sum())
    return {
        "curve": metrics.decimate(xs, ys),
        "effort_at": {
            str(point): metrics.effort_for(xs, ys, point * positives)
            for point in COVERAGE_POINTS
        },
        "caught_at_budget": metrics.caught_at(xs, ys, budget),
        "coverage_at_budget": metrics.caught_at(xs, ys, budget) / positives,
    }


def retrospective(frame: pd.DataFrame) -> dict[str, Any]:
    """Rank today's catalogue with today's scores against today's KEV.

    This is the comparison the industry quotes. It flatters EPSS, because EPSS
    is trained on exploitation signals and KEV is the exploitation ground truth:
    the forecaster has already seen the answers. Reported because it is the
    number people expect, then dismantled by :func:`prospective`.
    """
    label = frame["in_kev"].to_numpy(dtype=float)
    positives, universe = float(label.sum()), len(frame)
    budget = float((frame["cvss_base"] >= CRITICAL).sum())

    xs_random = np.array([0.0, universe])
    ys_random = np.array([0.0, positives])

    return {
        "universe": universe,
        "positives": int(positives),
        "budget": int(budget),
        "budget_definition": f"every CVE with a CVSS base score >= {CRITICAL}",
        "strategies": {
            "cvss": _curve_block(metrics.strategy_scores(frame, "cvss_base"), label, budget),
            "epss": _curve_block(metrics.strategy_scores(frame, "epss"), label, budget),
            "random": {
                "curve": metrics.decimate(xs_random, ys_random),
                "effort_at": {
                    str(point): point * universe for point in COVERAGE_POINTS
                },
                "caught_at_budget": positives * budget / universe,
                "coverage_at_budget": budget / universe,
            },
        },
    }


def prospective(frame: pd.DataFrame, cutoff: str) -> dict[str, Any] | None:
    """Score frozen rankings against vulnerabilities exploited afterwards.

    Both the EPSS scores and the universe are rewound to ``cutoff``: only CVEs
    published by then and carrying a score by then are in play, which is what a
    defender would have had on their screen that morning. The positives are the
    CVEs CISA added to KEV *after* that date, so no strategy has seen them.

    One asymmetry is left in on purpose and disclosed: CVSS is read as of today
    rather than frozen, because the mirror carries no score history. That hands
    CVSS an advantage, and it still loses at the head of the queue.
    """
    epss_path = paths.epss_snapshot(cutoff)
    if not epss_path.exists():
        return None
    frozen = build.load_epss(epss_path)[["cve_id", "epss"]].rename(
        columns={"epss": "epss_frozen"}
    )

    at_cutoff = frame[frame["published"] < pd.Timestamp(cutoff)].merge(
        frozen, on="cve_id", how="inner"
    )
    later = frame.loc[
        frame["kev_date_added"].astype("string") > cutoff, "cve_id"
    ]
    label = at_cutoff["cve_id"].isin(set(later)).to_numpy(dtype=float)
    positives = float(label.sum())
    if positives < 10:
        return None

    budget = float((at_cutoff["cvss_base"] >= CRITICAL).sum())
    cvss = metrics.strategy_scores(at_cutoff, "cvss_base")
    epss = metrics.strategy_scores(at_cutoff, "epss_frozen")
    positive_index = np.flatnonzero(label)

    result: dict[str, Any] = {
        "cutoff": cutoff,
        "epss_model": build.epss_metadata(epss_path).get("model_version"),
        "universe": len(at_cutoff),
        "newly_exploited_total": int((frame["kev_date_added"].astype("string") > cutoff).sum()),
        "positives": int(positives),
        "budget": int(budget),
        "strategies": {
            "cvss": _curve_block(cvss, label, budget),
            "epss": _curve_block(epss, label, budget),
        },
    }
    for name, score in (("cvss", cvss), ("epss", epss)):
        low, high = metrics.bootstrap_coverage(
            metrics.average_ranks(score), positive_index, budget
        )
        result["strategies"][name]["coverage_ci95"] = [low, high]

    effort = {
        name: result["strategies"][name]["effort_at"] for name in ("cvss", "epss")
    }
    result["effort_ratio"] = {
        point: effort["cvss"][point] / effort["epss"][point]
        for point in effort["cvss"]
    }
    return result


def sla(frame: pd.DataFrame) -> dict[str, Any]:
    """What BOD 22-01 actually grants, measured rather than assumed."""
    kev = frame[frame["in_kev"]].copy()
    added = pd.to_datetime(kev["kev_date_added"].astype("string"))
    due = pd.to_datetime(kev["kev_due_date"].astype("string"))
    window = (due - added).dt.days

    by_year = (
        window.groupby(added.dt.year)
        .agg(["count", "median", "mean"])
        .round(1)
        .rename_axis("year")
        .reset_index()
    )
    return {
        "count": int(len(kev)),
        "ransomware": int(kev["kev_ransomware"].sum()),
        "window_days": {
            "median": float(window.median()),
            "mean": float(window.mean()),
            "min": int(window.min()),
            "max": int(window.max()),
            "p90": float(window.quantile(0.9)),
        },
        "window_histogram": {
            str(int(days)): int(count)
            for days, count in window.value_counts().sort_index().items()
        },
        "by_year": by_year.to_dict(orient="records"),
        "additions_by_month": {
            str(period): int(count)
            for period, count in added.dt.to_period("M").value_counts().sort_index().items()
        },
    }


def analyse(frame: pd.DataFrame | None = None, *, verbose: bool = False) -> dict[str, Any]:
    frame = build.build() if frame is None else frame
    epss_meta = build.epss_metadata()
    kev_catalog = json.loads(paths.KEV_JSON.read_text())

    result = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "kev_catalog_version": kev_catalog["catalogVersion"],
        "kev_released": kev_catalog["dateReleased"],
        "epss_score_date": epss_meta.get("score_date"),
        "epss_model_version": epss_meta.get("model_version"),
        "nvd_notice": sources.NVD_MIRROR_NOTICE,
        "retrospective": retrospective(frame),
        "prospective": [
            block
            for block in (prospective(frame, cutoff) for cutoff in sources.CUTOFFS)
            if block is not None
        ],
        "sla": sla(frame),
    }
    if verbose:
        retro = result["retrospective"]["strategies"]
        print(
            f"  retrospective 80%: cvss {retro['cvss']['effort_at']['0.8']:,.0f} "
            f"vs epss {retro['epss']['effort_at']['0.8']:,.0f}"
        )
        for block in result["prospective"]:
            print(
                f"  {block['cutoff']}  n={block['positives']:>4}  "
                f"cvss {block['strategies']['cvss']['coverage_at_budget']:.0%}  "
                f"epss {block['strategies']['epss']['coverage_at_budget']:.0%}  "
                f"ratio80 {block['effort_ratio']['0.8']:.1f}x"
            )
    return result


def write(result: dict[str, Any], path: Path | None = None) -> Path:
    path = path or paths.ANALYSIS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=1) + "\n")
    return path


if __name__ == "__main__":
    table = pd.read_parquet(paths.VULNERABILITIES)
    destination = write(analyse(table, verbose=True))
    print(
        f"-> {destination.relative_to(paths.ROOT)} "
        f"({destination.stat().st_size / 1e6:.2f} MB)"
    )
