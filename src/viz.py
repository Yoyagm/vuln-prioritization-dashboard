"""Chart construction, kept out of the app so it can be read and tested.

Colour is assigned to an entity once, here, and never varies with rank or with
how many series a filter leaves on screen: CVSS is always blue, EPSS is always
orange, and the random baseline is deliberately not a series colour at all --
it is grey and dashed, because it is a reference, not a competitor.

The two-series palette clears the colour-vision checks on this surface (worst
pair ΔE 24.7 simulated, 33.6 unsimulated), so the two lines stay distinguishable
without relying on the legend.
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go

# Entity colours. Fixed assignment, never cycled.
CVSS = "#2a78d6"
EPSS = "#eb6834"
BASELINE = "#898781"

# Status, reserved: never reused as a series colour.
CRITICAL = "#d03b3b"
GOOD = "#0ca30c"

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

LABELS = {"cvss": "CVSS base score", "epss": "EPSS", "random": "Random"}
COLOURS = {"cvss": CVSS, "epss": EPSS, "random": BASELINE}


def _layout(
    fig: go.Figure, *, height: int = 380, hovermode: str = "x unified", **kwargs: Any
) -> go.Figure:
    """Recessive chrome, legible ink, no decoration."""
    fig.update_layout(
        height=height,
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font=dict(color=INK, size=13),
        margin=dict(l=10, r=10, t=30, b=10),
        hovermode=hovermode,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
        **kwargs,
    )
    fig.update_xaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, title_font_size=12)
    fig.update_yaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, title_font_size=12)
    return fig


def effort_curve(analysis: dict[str, Any], *, log_x: bool = True) -> go.Figure:
    """Coverage against effort: how much of KEV you cover per CVE patched.

    The x axis is logarithmic by default because the interesting part is the
    first few thousand CVEs, and on a linear axis the two strategies are an
    indistinguishable smear against 359,399.
    """
    import numpy as np

    block = analysis["retrospective"]
    positives = block["positives"]
    universe = block["universe"]
    fig = go.Figure()

    # The random baseline is a straight line in linear space, which is exactly
    # two points -- and two points cannot be drawn on a log axis, since x=0 has
    # no position on it. Sampled instead, so the reference actually appears.
    random_x = np.logspace(0, np.log10(universe), 200)
    fig.add_trace(
        go.Scatter(
            x=random_x,
            y=100 * random_x / universe,
            name=LABELS["random"],
            mode="lines",
            # Drawn first so the strategies sit above it, listed last so the
            # legend still reads CVSS, EPSS, then the reference.
            legendrank=3,
            line=dict(color=BASELINE, width=2, dash="dash"),
            hovertemplate="%{y:.1f}% of KEV after %{x:,.0f} CVEs<extra>Random</extra>",
        )
    )

    for key in ("cvss", "epss"):
        curve = block["strategies"][key]["curve"]
        fig.add_trace(
            go.Scatter(
                x=[point[0] for point in curve],
                y=[100 * point[1] / positives for point in curve],
                name=LABELS[key],
                mode="lines",
                legendrank=1 if key == "cvss" else 2,
                line=dict(color=COLOURS[key], width=2),
                hovertemplate="%{y:.0f}% of KEV after %{x:,.0f} CVEs<extra>"
                + LABELS[key]
                + "</extra>",
            )
        )

    fig.add_hline(
        y=80,
        line=dict(color=AXIS, width=1, dash="dot"),
        annotation_text="80% covered",
        annotation_position="top left",
        annotation_font=dict(color=INK_MUTED, size=11),
    )

    # The headline lives on the chart, not only in the caption: mark where each
    # strategy crosses 80 % and label the cost of getting there.
    for key in ("epss", "cvss"):
        crossing = block["strategies"][key]["effort_at"]["0.8"]
        fig.add_trace(
            go.Scatter(
                x=[crossing],
                y=[80],
                mode="markers+text",
                marker=dict(color=COLOURS[key], size=11, line=dict(color=SURFACE, width=2)),
                text=[f"  {crossing:,.0f}"],
                textposition="middle right" if key == "epss" else "top center",
                textfont=dict(color=COLOURS[key], size=12),
                showlegend=False,
                hoverinfo="skip",
            )
        )
    _layout(fig)
    fig.update_xaxes(
        title="CVEs patched, in priority order",
        type="log" if log_x else "linear",
    )
    fig.update_yaxes(title="% of exploited CVEs covered", range=[0, 102], ticksuffix="%")
    return fig


def prospective_dots(analysis: dict[str, Any]) -> go.Figure:
    """Frozen-score results per cutoff, with their uncertainty.

    A dot plot rather than bars: the quantity is a share with a confidence
    interval, and bars would imply a magnitude growing from zero while hiding
    the interval that matters more than the point.
    """
    blocks = analysis["prospective"]
    cutoffs = [block["cutoff"] for block in blocks]
    fig = go.Figure()
    for key in ("cvss", "epss"):
        values = [100 * block["strategies"][key]["coverage_at_budget"] for block in blocks]
        low = [
            100 * (block["strategies"][key]["coverage_at_budget"]
                   - block["strategies"][key]["coverage_ci95"][0])
            for block in blocks
        ]
        high = [
            100 * (block["strategies"][key]["coverage_ci95"][1]
                   - block["strategies"][key]["coverage_at_budget"])
            for block in blocks
        ]
        fig.add_trace(
            go.Scatter(
                x=cutoffs,
                y=values,
                name=LABELS[key],
                mode="markers",
                marker=dict(color=COLOURS[key], size=12, line=dict(color=SURFACE, width=2)),
                error_y=dict(type="data", symmetric=False, array=high, arrayminus=low,
                             color=COLOURS[key], thickness=2, width=6),
                hovertemplate="%{y:.0f}% caught<extra>" + LABELS[key] + "</extra>",
            )
        )
    _layout(fig, height=340)
    fig.update_xaxes(title="Scores frozen at")
    fig.update_yaxes(
        title="% of later-exploited CVEs caught", range=[0, 80], ticksuffix="%"
    )
    return fig


def sla_windows(analysis: dict[str, Any], *, top: int = 6) -> go.Figure:
    """How many days CISA grants, and how often it grants that many.

    Not a histogram. CISA does not draw these from a distribution -- it picks
    from a handful of fixed windows, and 17 distinct values across 1,665
    entries with three of them holding 92 % is categorical data. Plotted on a
    continuous axis it reads as three spikes in an empty field; plotted as
    named categories it reads as the policy it actually is.
    """
    histogram = analysis["sla"]["window_histogram"]
    ranked = sorted(((int(day), count) for day, count in histogram.items()),
                    key=lambda pair: -pair[1])
    head, tail = ranked[:top], ranked[top:]
    labels = [f"{day} days" for day, _ in head]
    counts = [count for _, count in head]
    if tail:
        labels.append(f"{len(tail)} other windows")
        counts.append(sum(count for _, count in tail))

    fig = go.Figure(
        go.Bar(
            x=counts[::-1],
            y=labels[::-1],
            orientation="h",
            marker=dict(color=CVSS, line=dict(color=SURFACE, width=2)),
            text=[f"{count:,}" for count in counts[::-1]],
            textposition="outside",
            textfont=dict(color=INK_MUTED, size=12),
            hovertemplate="%{x:,} vulnerabilities<extra>%{y}</extra>",
        )
    )
    _layout(fig, height=300, hovermode="closest")
    fig.update_xaxes(title="Vulnerabilities", showgrid=False, showticklabels=False)
    fig.update_yaxes(title=None, automargin=True)
    return fig


def backlog(frame, weekly_rate: int) -> tuple[go.Figure, dict[str, float]]:
    """Simulate working the KEV queue at a fixed rate.

    Deterministic single-server queue: items arrive on the day CISA lists them
    and are worked oldest-first at ``weekly_rate`` per week. An item is late if
    it finishes after its deadline. The output people react to is not the chart,
    it is the number of overdue days the rate buys an attacker.
    """
    import pandas as pd

    kev = frame[frame["in_kev"]].copy()
    added = pd.to_datetime(kev["kev_date_added"].astype("string"))
    due = pd.to_datetime(kev["kev_due_date"].astype("string"))
    order = added.sort_values().index
    added, due = added.loc[order], due.loc[order]

    per_day = weekly_rate / 7.0
    free_at = added.iloc[0]
    finished = []
    for arrival in added:
        start = max(arrival, free_at)
        completion = start + pd.Timedelta(days=1 / per_day)
        finished.append(completion)
        free_at = completion
    finished = pd.Series(finished, index=added.index)

    late_days = (finished - due).dt.days.clip(lower=0)
    monthly = (
        late_days.groupby(added.dt.to_period("M").astype(str)).sum().sort_index()
    )

    fig = go.Figure(
        go.Bar(
            x=list(monthly.index),
            y=list(monthly.values),
            marker=dict(color=CRITICAL, line=dict(color=SURFACE, width=2)),
            hovertemplate="%{y:,} overdue days added in %{x}<extra></extra>",
        )
    )
    _layout(fig, height=320, hovermode="closest")
    fig.update_xaxes(title="Month the vulnerability was listed")
    fig.update_yaxes(title="Overdue days accumulated")

    summary = {
        "late": int((late_days > 0).sum()),
        "total": int(len(late_days)),
        "overdue_days": int(late_days.sum()),
        "worst": int(late_days.max()),
    }
    return fig, summary


def top_bar(labels: list[str], values: list[int], *, title: str, colour: str = CVSS) -> go.Figure:
    """Horizontal bars for ranked categories -- the only honest form for names."""
    fig = go.Figure(
        go.Bar(
            x=values[::-1],
            y=labels[::-1],
            orientation="h",
            marker=dict(color=colour, line=dict(color=SURFACE, width=2)),
            hovertemplate="%{y}: %{x:,}<extra></extra>",
        )
    )
    _layout(fig, height=max(320, 22 * len(labels)), hovermode="closest")
    fig.update_xaxes(title=title)
    fig.update_yaxes(title=None, automargin=True)
    return fig


def additions_over_time(analysis: dict[str, Any]) -> go.Figure:
    """When CISA added things, monthly."""
    series = analysis["sla"]["additions_by_month"]
    months = sorted(series)
    fig = go.Figure(
        go.Scatter(
            x=months,
            y=[series[month] for month in months],
            mode="lines",
            line=dict(color=CVSS, width=2),
            fill="tozeroy",
            fillcolor="rgba(42,120,214,0.12)",
            hovertemplate="%{y} added in %{x}<extra></extra>",
        )
    )
    _layout(fig, height=300)
    fig.update_xaxes(title=None)
    fig.update_yaxes(title="Vulnerabilities added")
    return fig
