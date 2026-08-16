# ADR 0005 — Streamlit for the app, year-by-year for the parse

**Status:** accepted, 2026-08-15

Two smaller decisions, recorded because both were live alternatives.

## Streamlit over Dash

**Context.** The deliverable needs a public URL a recruiter can open, at zero cost, with no
infrastructure to keep alive.

**Decision.** Streamlit, deployed on Community Cloud.

**Consequences.** The deploy is a repository connection rather than a server: no container, no
process manager, no certificate. Community Cloud supports Python 3.10 through 3.14 and defaults to
3.12, pinned here with `runtime.txt`. The cost is layout control — Streamlit's grid is coarse, and
some of the polish in these views went into working with it rather than around it.

**Rejected.** *Dash* gives finer layout control and a real callback model, and needs somewhere to
run: a free tier that sleeps, or a paid one. *A static export* (nbconvert, Quarto) would deploy
anywhere but loses the filtering and the remediation-rate slider, which are the parts that turn the
data into a decision.

## Year-by-year parsing, never the combined file

**Context.** The mirror publishes both `CVE-all.json.xz` (96 MB, **3.0 GB expanded**) and one file
per year (the largest being 12 MB).

**Decision.** Always walk the annual files. Never load the combined one.

**Consequences.** The JSON parse is bounded by the largest single year — 1.84 GB for 2025 — rather
than by the whole catalogue. The full extract of 377,359 CVEs runs in **20 seconds** and produces a
5.7 MB Parquet file. `src/extract.py` accepts a directory so the same code path runs against a
12-CVE fixture in tests.

The whole walk still peaks at **3.5–4.8 GB**, because the extracted rows are held as dicts until the
DataFrame is built. That spread is run-to-run allocator variance on identical code, which is worth
recording: an earlier attempt to "fix" it by building one DataFrame per year was comparing noise and
changed nothing. `test_the_full_extract_stays_inside_its_memory_budget` asserts 6 GB — chosen to sit
above the observed spread and far below what the combined file would cost, since the regression
worth catching is someone deciding `CVE-all.json.xz` is simpler, not a few hundred megabytes of
drift.

**Rejected.** *Loading `CVE-all.json.xz` whole.* 3 GB of JSON becomes far more than 3 GB of Python
objects; it would work on a developer laptop with enough RAM and fail everywhere else, for no gain
over the annual files. *Streaming it with `ijson`.* This is the real lever on the remaining 3.5 GB
and it was still declined: the pipeline runs offline on a laptop, never in the deployed app, so the
memory buys nothing that a dependency and a harder-to-test code path would be worth. Revisit if the
extract ever needs to run in CI.
