# Spec — Vulnerability prioritisation dashboard (CISA KEV + EPSS + NVD)

**Goal.** Answer one question with public data and defensible measurement: *of the 359,399 live
CVEs, which ones do you patch first?* Ship it as a public Streamlit app and a README that a hiring
manager can read in thirty seconds.

**Audience.** Security and GRC hiring managers, and the recruiters who screen for them. Secondary:
anyone who has to defend a patching queue to a stakeholder.

**The finding comes first, the dashboard second.** A dashboard over these three feeds already exists
several times on GitHub. What does not exist is an honest measurement of whether the metrics it
draws are worth anything — and the honest answer is more interesting than the marketing one.

---

## 1. The finding this project is built around

Measured during phase 0 on the 2026-08-15 snapshot. These numbers are already reproduced (spike
scripts, not yet production code) and the pipeline must regenerate them:

**Retrospective comparison — the number the industry quotes.** Rank all 359,399 non-rejected CVEs
and count how many you must patch to cover 80 % of the 1,665 CVEs CISA has confirmed exploited:

| Strategy | 50 % of KEV | 80 % of KEV | 90 % of KEV |
|---|---|---|---|
| CVSS base score | 68,835 | 137,952 | 196,334 |
| EPSS | 3,850 | 22,736 | 51,162 |
| Random | 179,700 | 287,519 | 323,459 |

EPSS looks **6.1× more efficient**. At an equal budget of 47,253 CVEs (every CVE at CVSS ≥ 9.0),
CVSS catches 35.4 % of KEV and EPSS catches 88.8 %.

**Prospective comparison — the honest one.** EPSS is trained on exploitation signals and KEV *is*
the exploitation ground truth, so the table above scores a forecaster against data it has already
seen. Freeze EPSS at a past date (FIRST publishes daily archives), keep only CVEs published by then,
and score against KEV entries CISA added *afterwards*. Five cutoffs, same experiment:

| Cutoff | Universe | Later exploited | Budget | CVSS caught | EPSS caught | EPSS 95 % CI | Effort ratio at 80 % |
|---|---|---|---|---|---|---|---|
| 2023-08-15 | 209,676 | 143 | 31,186 | 36 % | 52 % | 43–59 % | 0.7× |
| 2024-02-15 | 224,656 | 133 | 33,719 | 33 % | 50 % | 41–59 % | 0.7× |
| 2024-08-15 | 245,116 | 139 | 35,700 | 36 % | 43 % | 35–52 % | 0.6× |
| 2025-02-15 | 266,600 | 112 | 37,778 | 29 % | 37 % | 29–46 % | 0.5× |
| 2025-08-15 | 289,890 | 86 | 39,980 | 30 % | 55 % | 45–65 % | 0.7× |

Two results, both stable across all five dates:

1. **EPSS genuinely beats CVSS at the top of the list.** Same budget, 1.4–1.8× the later-exploited
   vulnerabilities caught.
2. **The 6.1× figure is mostly measurement artefact.** Once scores are frozen, EPSS needs *more*
   work than CVSS to reach 80 % coverage (ratio 0.5–0.7×, every cutoff): its tail buries a real
   slice of what later gets exploited.

The headline for the README is the pair, not either half. The operational conclusion the dashboard
implements: **KEV first, then EPSS for the head of the queue, with CVSS retained as the tail-risk
guard** — the hybrid is the product, and the curve is the evidence for it.

---

## 2. Scope

**In.** Offline ingest of three public feeds; a joined artefact committed to the repo; the effort
curve analysis, retrospective and prospective; a Streamlit dashboard with four views; BOD 22-01 SLA
analysis as a secondary view; tests; README as landing page; public deploy.

**Out.** Live scanning or asset inventory. Any per-organisation data. CVSS temporal/environmental
scoring. SSVC decision-tree modelling (the field is carried, not modelled). Alerting, auth, a
database, a REST API. Automatic daily refresh — refresh is a documented command, not a cron.

---

## 3. Data contracts

Artefact names are fixed; the tests assert these schemas literally.

### 3.1 `data/raw/` — gitignored, rebuilt by `make ingest`

| File | Source | Notes |
|---|---|---|
| `kev.json` | CISA KEV feed | one request, ~1.5 MB |
| `epss_scores-current.csv.gz` | EPSS daily dump | 302 redirect; **line 1 is a comment**, header is line 2 |
| `epss_<YYYY-MM-DD>.csv.gz` | EPSS archive, one per cutoff | same layout |
| `nvd-annual/CVE-<year>.json.xz` | fkie-cad mirror, 1999–2026 | 109 MB total, ~30 s |
| `MANIFEST.json` | written by the ingest | per file: URL, bytes, sha256, fetched-at, row count |

`MANIFEST.json` is what makes a run reproducible after the feeds move on. It is **committed**; the
files it describes are not.

### 3.2 `data/processed/vulnerabilities.parquet` — committed, budget ≤ 12 MB

One row per non-rejected CVE. The slim extract measured 5.5 MB for 377,359 rows, so the budget
holds with room.

| Column | Type | Unit / domain | Null? |
|---|---|---|---|
| `cve_id` | string | `CVE-YYYY-NNNN…`, unique, primary key | no |
| `published` | timestamp[us] | UTC, from NVD | no |
| `vuln_status` | category | NVD `vulnStatus`; `Rejected` rows are dropped before writing | no |
| `cvss_base` | float32 | 0.0–10.0 | **yes** — 1,478 CVEs (0.4 %) have no score |
| `cvss_severity` | category | LOW/MEDIUM/HIGH/CRITICAL | yes, iff `cvss_base` is null |
| `cvss_version` | category | `4.0`/`3.1`/`3.0`/`2.0` — which metric was used | yes, iff `cvss_base` is null |
| `epss` | float32 | 0.0–1.0, probability of exploitation in 30 days | **yes** in principle; 0 nulls observed |
| `epss_percentile` | float32 | 0.0–1.0 | same as `epss` |
| `in_kev` | bool | present in the KEV catalogue | no |
| `kev_date_added` | date32 | KEV `dateAdded` | yes, iff not `in_kev` |
| `kev_due_date` | date32 | KEV `dueDate`, BOD 22-01 deadline | yes, iff not `in_kev` |
| `kev_ransomware` | bool | KEV `knownRansomwareCampaignUse == "Known"` | no; false when not in KEV |
| `kev_vendor` | string | KEV `vendorProject` | yes, iff not `in_kev` |
| `kev_product` | string | KEV `product` | yes, iff not `in_kev` |
| `ssvc_exploitation` | category | CISA SSVC `exploitation` option | yes — minority of CVEs |
| `cwe_ids` | list[string] | de-duplicated CWE identifiers | yes, empty list allowed |

**CVSS selection rule** (must be implemented exactly, it is a real source of silent disagreement):
prefer `type == "Primary"` **and** `source == "nvd@nist.gov"`; else the first `Primary`; else the
first entry. Version preference `4.0 > 3.1 > 3.0 > 2.0`, first present wins, and the version used is
recorded in `cvss_version` rather than silently mixed.

### 3.3 `data/processed/analysis.json` — committed, budget ≤ 2 MB

Every number the README and the dashboard display comes from this file. Nothing is typed by hand
into prose. Shape:

```jsonc
{
  "generated_at": "…", "kev_catalog_version": "…", "epss_score_date": "…",
  "universe": {"total": 377359, "rejected": 17960, "analysed": 359399},
  "retrospective": {
    "curves": {"cvss": [[x, y], …], "epss": [[x, y], …], "random": [[x, y], …]},
    "effort_at": {"cvss": {"0.5": …, "0.8": …, "0.9": …}, "epss": {…}},
    "equal_budget": {"budget": 47253, "cvss_coverage": 0.354, "epss_coverage": 0.888}
  },
  "prospective": [ {"cutoff": "2025-08-15", "universe": …, "positives": 86,
                    "budget": …, "cvss_coverage": …, "epss_coverage": …,
                    "epss_ci95": […, …], "effort_ratio_80": 0.7}, … ],
  "sla": { … see §5.2 … }
}
```

Curves are **decimated to ≤ 500 points per series** before serialisation — the raw curve has one
point per distinct score block and would blow the size budget for no visual gain.

### 3.4 Metric contract — how a curve is computed

Non-negotiable, because it is the one place where a plausible implementation gives a wrong answer:

- A strategy is a score vector; higher means patch sooner.
- **Ties are averaged, never broken.** Tens of thousands of CVEs share a CVSS of exactly 9.8. Any
  implementation that lets `sort` settle those ties is measuring CVE-id alphabetical order. The
  curve is therefore evaluated at *block* boundaries — one block per distinct score — and read
  linearly in between, which is exactly the expected value under uniformly random ordering inside
  the block.
- **Missing score sorts last** for every strategy, so no strategy is flattered by absent data.
- A **random baseline** is always plotted. Without it the two curves have no scale.
- Prospective runs freeze EPSS at the cutoff and restrict the universe to `published < cutoff`
  **and** present in that day's EPSS dump — what a defender could actually have had in hand.
- Uncertainty is bootstrapped **over the positives** (2,000 resamples, seed pinned), because that
  is where the sampling noise lives: 86–143 exploited CVEs per cutoff, not 300,000 universe rows.

---

## 4. Known limitations, stated in the README rather than buried

1. **KEV is biased and incomplete.** It is what CISA has confirmed and published, not what is
   exploited. Absence from KEV is not evidence of safety.
2. **CVSS scores are read as of today, not frozen at the cutoff.** NVD scores can be revised. This
   is a real advantage handed to CVSS in the prospective test, and it still loses at the head of the
   list — so the direction of the finding survives the caveat, and the caveat gets said.
3. **Small positive counts.** 86–143 exploited CVEs per cutoff. Hence bootstrap intervals on every
   prospective claim, and no claim made from a single cutoff.
4. **Vulnerabilities published after the cutoff are excluded** from prospective runs (180 of the 266
   in the 2025-08-15 window). Neither strategy can score a CVE that does not exist yet; this is a
   statement about triaging a backlog, not about zero-days.
5. **The NVD mirror is a third party.** `fkie-cad/nvd-json-data-feeds` "uses and redistributes data
   from the NVD API but is neither endorsed nor certified by the NVD" — quoted verbatim in the
   README.

---

## 5. Dashboard — every view answers a stated question

No chart exists for decoration. Four views, each with the operator question it answers written
above it in the app itself.

### 5.1 "What do I patch this week?" (landing view)
The queue. Table of CVEs ranked by the hybrid policy (KEV first, ransomware-flagged KEV above the
rest, then EPSS descending, CVSS shown alongside), filterable by vendor, product, CVSS band, EPSS
threshold and KEV-only. Exports the visible queue to CSV — the artefact a stakeholder actually asks
for. Top of the page: how many CVEs the current filter selects, and what share of KEV it covers.

### 5.2 "Are we inside the deadline?" (SLA view, BOD 22-01)
KEV only. Distribution of the window CISA grants (`dueDate − dateAdded`), how that window has
changed over time, and a simulated backlog: given a remediation rate of *N* CVEs/week — a slider —
how many KEV items breach their due date, and how many cumulative days of overdue exposure that
buys an attacker. The slider is the point: it turns "we need more capacity" into a number.

### 5.3 "Does CVSS predict exploitation?" (the finding)
The effort/coverage curves, retrospective and prospective side by side, with the random baseline and
the bootstrap band. A cutoff selector for the five prospective dates. The two conclusions from §1
are written on the page as prose, not left for the reader to infer from a chart.

### 5.4 "What is the catalogue made of?" (context)
KEV composition: top vendors and products, ransomware share (349 of 1,665), CWE distribution, and
additions per month. This is the view that gives a recruiter something recognisable in five seconds.

**Performance budget.** Cold start under 5 s on Streamlit Community Cloud. The app loads two
committed artefacts and computes nothing heavier than filtering and aggregation; every curve is
precomputed. `st.cache_data` on the loaders.

---

## 6. Milestones

Each must be verifiable by running the stated command and checking the stated result. Do not start a
milestone with the previous one's tests red.

- [x] **M1 — Reproducible ingest.**
  `src/ingest.py` fetches all four sources into `data/raw/` and writes `MANIFEST.json` (URL, bytes,
  sha256, fetched-at, row count each). Handles the EPSS 302 and the line-1 comment; retries with
  backoff; a **progress watchdog**, not just a socket timeout — that is precisely how the NVD API
  attempt hung for 105 minutes.
  *Verify:* `rm -rf data/raw && make ingest` completes under 3 minutes and
  `pytest tests/test_ingest.py` passes offline against fixtures. `MANIFEST.json` lists ≥ 34 files.

- [x] **M2 — Extract and join.**
  `src/extract.py` walks the annual NVD files year by year (never the 3 GB file whole) and
  `src/build.py` joins KEV and EPSS into `data/processed/vulnerabilities.parquet`.
  *Verify:* `make build` produces the file; `pytest tests/test_schema.py` asserts every column,
  dtype and null rule in §3.2, that `cve_id` is unique, that no `Rejected` row survives, and that
  the file is ≤ 12 MB. Peak RSS stays under 2 GB (asserted in the test).

- [x] **M3 — The measurement.**
  `src/metrics.py` implements §3.4 and `src/analyse.py` writes `data/processed/analysis.json`.
  *Verify:* `make analyse` reproduces the §1 tables within ±1 % of the values recorded there.
  `pytest tests/test_metrics.py` includes a **tie-handling guard with a negative control**: a
  hand-built fixture where a naive `sort` gives a knowably wrong answer and the correct
  implementation gives the known-right one — plus a companion test proving the guard fails when the
  averaging is removed. A guard that cannot fail protects nothing.

- [ ] **M4 — Dashboard.**
  `app.py` with the four views of §5, reading only the two committed artefacts.
  *Verify:* `make app` serves locally; a smoke test drives it headless, asserts each view renders
  without exception and that cold start is under 5 s; one screenshot per view saved to `docs/img/`.

- [ ] **M5 — Test suite and reproducibility.**
  *Verify:* `make test` green with **no network access** (a fixture-level guard fails any test that
  attempts a socket). `requirements.txt` generated by `uv pip freeze`, `runtime.txt` pinned to
  `3.12`, and a from-scratch `uv venv && uv pip install -r requirements.txt && make test` works in a
  clean clone.

- [ ] **M6 — README as landing page.**
  Problem, data sources with licence notices, method, the §1 tables, the four screenshots, the
  limitations of §4, and a reproduce-in-three-commands block. English. Skills, named explicitly:
  vulnerability prioritisation, KEV/EPSS/CVSS, risk-based patching, stakeholder-ready dashboards.
  Plus `docs/adr/` with the four decisions of §7.
  *Verify:* every number in the README traced to `analysis.json` by a test that parses both and
  compares — no hand-typed figures.

- [ ] **M7 — Public deploy.**
  Push to `github.com/Yoyagm/vuln-prioritization-dashboard` (public, at this point and not before)
  and deploy to Streamlit Community Cloud.
  *Verify:* the public URL loads all four views; the README badge links to it; a clean clone of the
  public repo passes `make test`.

---

## 7. Decisions already closed (ADRs to write in `docs/adr/`)

1. **NVD universe from the fkie-cad mirror, not the official API.** The API was tried and abandoned:
   189 pages, 255 s/page measured (~12 h), and a connection that hangs while dribbling bytes so the
   socket timeout never fires. The mirror serves the whole catalogue in 12 s with an identical
   schema. Cost accepted: a third-party dependency and a licence notice. The API is retained for the
   KEV subset, where `?hasKev` returns all 1,665 in one request.
2. **Committed artefacts, not live ingest.** The app must not download 109 MB or parse 3 GB at cold
   start. Ingest runs offline; the app reads two small committed files. Cost: figures are as of the
   snapshot, so the snapshot date is displayed in the app.
3. **Streamlit over Dash.** Community Cloud is free, supports Python 3.10–3.14 and defaults to 3.12;
   the deploy is a URL rather than a server. Cost: less layout control.
4. **Year-by-year processing.** 3 GB does not fit comfortably in memory; an annual file loads in
   1.5 s and the whole catalogue extracts in 20 s.

## 8. Testing rules

- No test touches the network. Fixtures are trimmed real payloads (≤ 50 CVEs), committed under
  `tests/fixtures/`, including at least one CVE with no CVSS, one `Rejected`, one KEV entry with
  ransomware use, one with only a v2 score, and one carrying SSVC.
- Every join gets an edge-case test: KEV id absent from NVD, NVD CVE absent from EPSS, duplicate
  ids, and a CVE whose CVSS metric list has no `Primary` entry.
- The metric guard of M3 is the load-bearing test of the project. It gets a negative control.
