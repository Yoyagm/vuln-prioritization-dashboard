# ADR 0002 — Commit small artefacts; never ingest at app start

**Status:** accepted, 2026-08-15

## Context

The dashboard is deployed on Streamlit Community Cloud: a free tier, one core, cold containers.
The inputs are 116 MB compressed and 3 GB expanded. A viewer arriving at the URL must not wait for
any of that.

## Decision

Split the work in two. Ingestion and analysis run offline, on a developer machine, producing two
small files that are **committed to the repository**:

- `data/processed/vulnerabilities.parquet` — 5.7 MB, one row per live CVE, budget 12 MB.
- `data/processed/analysis.json` — 0.17 MB, every published figure, budget 2 MB.

The app reads those two files and does nothing heavier than filtering and aggregation. Curves are
precomputed and decimated to at most 500 points per series before serialisation.

## Consequences

- Cold start is **under a second** for the data load, and the smoke test fails the build if the
  whole first render exceeds five seconds.
- The figures are as of a snapshot, not live. So the snapshot date is displayed in the sidebar and
  recorded in `analysis.json`, and refreshing is a documented command (`make data`) rather than a
  hidden cron.
- Two binary-ish files live in git history. At 5.9 MB combined per refresh this is acceptable for a
  project refreshed by hand; if it were refreshed daily it would not be.

## Rejected

**Fetching the feeds at app start.** Even the small feeds — KEV at 1.5 MB and EPSS at 2.5 MB — add
seconds and a network dependency to every cold container, and the NVD portion is impossible.

**A database.** Nothing here needs one: the working set is a single 5.7 MB table read whole, and a
database would add an operational dependency to a project whose deployment story is "push to a free
tier".
