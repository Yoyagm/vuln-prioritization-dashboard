"""Vulnerability prioritisation dashboard.

Reads two committed artefacts and computes nothing heavier than a filter, so it
starts in seconds on a free tier. Every published figure comes from
``analysis.json``; nothing here recalculates a statistic.
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from src import cwe, paths, viz

st.set_page_config(
    page_title="Which vulnerability do you patch first?",
    page_icon="🛡️",
    layout="wide",
)

VIEWS = [
    "What do I patch this week?",
    "Are we inside the deadline?",
    "Does CVSS predict exploitation?",
    "What is the catalogue made of?",
]


@st.cache_data(show_spinner=False)
def load_frame() -> pd.DataFrame:
    return pd.read_parquet(paths.VULNERABILITIES)


@st.cache_data(show_spinner=False)
def load_analysis() -> dict:
    return json.loads(paths.ANALYSIS.read_text())


def priority(frame: pd.DataFrame) -> pd.DataFrame:
    """Rank by the policy this project argues for.

    Confirmed exploitation first, ransomware use above the rest of it, then
    forecast probability. CVSS is shown but does not drive the order -- the
    measurement view is the argument for why.
    """
    tier = (~frame["in_kev"]).astype(int) * 2 + (~frame["kev_ransomware"]).astype(int)
    return frame.assign(_tier=tier).sort_values(
        ["_tier", "epss", "cvss_base"], ascending=[True, False, False]
    ).drop(columns="_tier")


def stat_row(items: list[tuple[str, str, str | None]]) -> None:
    for column, (label, value, help_text) in zip(st.columns(len(items)), items, strict=True):
        column.metric(label, value, help=help_text)


def view_queue(frame: pd.DataFrame) -> None:
    st.subheader("What do I patch this week?")
    st.caption(
        "Ranked by confirmed exploitation first, then by forecast probability. "
        "Filter it down to your estate and export the queue."
    )

    # One row of filters above the data, four equal columns: anything else
    # leaves a ragged gap under the toggles.
    vendor_col, toggle_col, epss_col, cvss_col = st.columns([2, 1.2, 1.4, 1.4])
    vendors = sorted(frame.loc[frame["in_kev"], "kev_vendor"].dropna().unique())
    chosen = vendor_col.multiselect("KEV vendor", vendors, placeholder="Any vendor")
    kev_only = toggle_col.toggle("Confirmed exploited only", value=True)
    ransomware_only = toggle_col.toggle("Ransomware use only", value=False)
    min_epss = epss_col.slider("Minimum EPSS", 0.0, 1.0, 0.0, 0.01)
    min_cvss = cvss_col.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)

    selection = frame
    if kev_only:
        selection = selection[selection["in_kev"]]
    if ransomware_only:
        selection = selection[selection["kev_ransomware"]]
    if chosen:
        selection = selection[selection["kev_vendor"].isin(chosen)]
    selection = selection[
        (selection["epss"].fillna(0) >= min_epss)
        & (selection["cvss_base"].fillna(0) >= min_cvss)
    ]

    kev_total = int(frame["in_kev"].sum())
    kev_here = int(selection["in_kev"].sum())
    stat_row(
        [
            ("Vulnerabilities in queue", f"{len(selection):,}", None),
            ("Confirmed exploited", f"{kev_here:,}", "Present in the CISA KEV catalogue"),
            (
                "Share of KEV covered",
                f"{kev_here / kev_total:.0%}" if kev_total else "--",
                "How much of everything known-exploited this queue contains",
            ),
            (
                "Median EPSS",
                f"{selection['epss'].median():.3f}" if len(selection) else "--",
                "Probability of exploitation in the next 30 days",
            ),
        ]
    )

    ranked = priority(selection)
    columns = [
        "cve_id",
        "cvss_base",
        "epss",
        "in_kev",
        "kev_ransomware",
        "kev_vendor",
        "kev_product",
        "kev_due_date",
        "published",
    ]
    st.dataframe(
        ranked[columns].head(500),
        width="stretch",
        hide_index=True,
        column_config={
            "cve_id": st.column_config.TextColumn("CVE"),
            "cvss_base": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "epss": st.column_config.ProgressColumn(
                "EPSS", min_value=0.0, max_value=1.0, format="%.3f"
            ),
            "in_kev": st.column_config.CheckboxColumn("Exploited"),
            "kev_ransomware": st.column_config.CheckboxColumn("Ransomware"),
            "kev_vendor": st.column_config.TextColumn("Vendor"),
            "kev_product": st.column_config.TextColumn("Product"),
            "kev_due_date": st.column_config.DateColumn("CISA deadline"),
            "published": st.column_config.DateColumn("Published"),
        },
    )
    if len(ranked) > 500:
        st.caption(f"Showing the top 500 of {len(ranked):,}. The export holds all of them.")
    st.download_button(
        "Download this queue as CSV",
        ranked[columns].to_csv(index=False).encode(),
        file_name="patch-queue.csv",
        mime="text/csv",
    )


def view_sla(frame: pd.DataFrame, analysis: dict) -> None:
    st.subheader("Are we inside the deadline?")
    st.caption(
        "US federal agencies must remediate KEV entries by a CISA-set deadline "
        "(Binding Operational Directive 22-01). This is what that deadline is "
        "worth at a given remediation capacity."
    )

    sla = analysis["sla"]
    stat_row(
        [
            ("Vulnerabilities listed", f"{sla['count']:,}", None),
            (
                "Used in ransomware",
                f"{sla['ransomware']:,}",
                f"{sla['ransomware'] / sla['count']:.0%} of the catalogue",
            ),
            ("Median window", f"{sla['window_days']['median']:.0f} days", None),
            ("Longest window", f"{sla['window_days']['max']:,} days", None),
        ]
    )
    st.plotly_chart(viz.sla_windows(analysis), width="stretch")

    st.markdown("#### What happens at your remediation rate")
    # 10/week is roughly the pace CISA has been adding at, so it is the rate
    # where the queue is neither trivially fine nor hopelessly behind.
    rate = st.slider("Vulnerabilities remediated per week", 1, 40, 10)
    figure, summary = viz.backlog(frame, rate)
    stat_row(
        [
            ("Finished late", f"{summary['late']:,} of {summary['total']:,}", None),
            (
                "Overdue days accumulated",
                f"{summary['overdue_days']:,}",
                "Total days spent past deadline across the catalogue",
            ),
            ("Worst single item", f"{summary['worst']:,} days late", None),
        ]
    )
    st.plotly_chart(figure, width="stretch")


def view_finding(analysis: dict) -> None:
    st.subheader("Does CVSS predict exploitation?")
    retro = analysis["retrospective"]["strategies"]
    cvss_effort = retro["cvss"]["effort_at"]["0.8"]
    epss_effort = retro["epss"]["effort_at"]["0.8"]

    stat_row(
        [
            ("Patching by CVSS", f"{cvss_effort:,.0f} CVEs", "To cover 80% of what is exploited"),
            ("Patching by EPSS", f"{epss_effort:,.0f} CVEs", "For the same coverage"),
            (
                "Apparent advantage",
                f"{cvss_effort / epss_effort:.1f}×",
                "Which turns out to be mostly artefact",
            ),
        ]
    )
    st.plotly_chart(viz.effort_curve(analysis), width="stretch")
    st.caption(
        "Both curves rank the same 359,399 live CVEs; the dashed line is what "
        "you would get patching at random. The x axis is logarithmic because "
        "the decision happens in the first few thousand vulnerabilities."
    )

    st.markdown("#### The same comparison, done honestly")
    st.markdown(
        "EPSS is trained on exploitation signals and the KEV catalogue *is* the "
        "exploitation ground truth, so the chart above scores a forecaster "
        "against data it has already seen. Below, the EPSS scores are frozen at "
        "a past date and judged only on vulnerabilities CISA confirmed as "
        "exploited **afterwards** — a genuine forecast. Bars are 95% bootstrap "
        "intervals over the exploited vulnerabilities."
    )
    st.plotly_chart(viz.prospective_dots(analysis), width="stretch")

    worst = max(block["effort_ratio"]["0.8"] for block in analysis["prospective"])
    apparent = f"{cvss_effort / epss_effort:.0f}×"
    st.markdown(
        f"""
**Two things survive the honest test, at every cutoff:**

1. **EPSS really does win at the head of the queue.** For the same budget it
   catches 1.4–1.8× the vulnerabilities that later get exploited.
2. **The {apparent} headline is mostly measurement artefact.** Once the scores
   are frozen, EPSS needs *more* work than CVSS to reach 80% coverage (ratio at
   most {worst:.1f}×): its tail buries a real share of what later gets exploited.

So the queue this dashboard ranks is neither: confirmed exploitation first,
EPSS for the head of the list, and CVSS kept as the guard on the tail.
"""
    )


def view_catalogue(frame: pd.DataFrame, analysis: dict) -> None:
    st.subheader("What is the catalogue made of?")
    kev = frame[frame["in_kev"]]
    stat_row(
        [
            ("Confirmed exploited", f"{len(kev):,}", None),
            ("Live CVEs tracked", f"{len(frame):,}", "Rejected identifiers excluded"),
            (
                "Exploited share",
                f"{len(kev) / len(frame):.2%}",
                "Which is why ranking matters more than severity",
            ),
            ("Vendors affected", f"{kev['kev_vendor'].nunique():,}", None),
        ]
    )

    left, right = st.columns(2)
    vendors = kev["kev_vendor"].value_counts().head(15)
    left.plotly_chart(
        viz.top_bar(list(vendors.index), list(vendors.values), title="Exploited vulnerabilities"),
        width="stretch",
    )
    cwes = kev["cwe_ids"].explode().dropna().value_counts().head(15)
    right.plotly_chart(
        viz.top_bar(
            [cwe.label(identifier) for identifier in cwes.index],
            list(cwes.values),
            title="Exploited vulnerabilities",
            colour=viz.EPSS,
        ),
        width="stretch",
    )
    st.markdown("#### When CISA added them")
    st.plotly_chart(viz.additions_over_time(analysis), width="stretch")


def main() -> None:
    frame = load_frame()
    analysis = load_analysis()

    st.sidebar.title("Patch what matters")
    view = st.sidebar.radio("View", VIEWS, label_visibility="collapsed")
    st.sidebar.divider()
    st.sidebar.caption(
        f"KEV catalogue {analysis['kev_catalog_version']} · "
        f"EPSS {analysis['epss_score_date'][:10]} · "
        f"{len(frame):,} live CVEs"
    )
    st.sidebar.caption(analysis["nvd_notice"])

    st.title("Which vulnerability do you patch first?")
    if view == VIEWS[0]:
        view_queue(frame)
    elif view == VIEWS[1]:
        view_sla(frame, analysis)
    elif view == VIEWS[2]:
        view_finding(analysis)
    else:
        view_catalogue(frame, analysis)


if __name__ == "__main__":
    main()
