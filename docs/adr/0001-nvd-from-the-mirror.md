# ADR 0001 — Take the NVD catalogue from the fkie-cad mirror, not the official API

**Status:** accepted, 2026-08-15

## Context

The project needs every live CVE with its CVSS metrics — 377,359 records — to compute a coverage
curve over the whole catalogue. The obvious source is the NVD's own REST API 2.0.

It was tried, and abandoned, with measurements:

- `totalResults = 377,370`, 189 pages of 2,000. Without an API key the documented limit is five
  requests per 30 seconds.
- The measured rate was **255 s per page**, not the ~15 s the first probe suggested, which puts a
  full pull at roughly **12 hours**.
- Worse, the connection **hangs without failing**. The server keeps the socket alive while
  dribbling bytes, so a `timeout=180` on `urlopen` never fires. One run sat on page 20 for
  **105 minutes** with the process alive and no error.

`fkie-cad/nvd-json-data-feeds` is a community reconstruction of the legacy JSON feeds, regenerated
daily, published as one `.xz` per year plus a combined file.

## Decision

Take the full catalogue from the mirror. Keep the official API for the KEV subset only, where
`?hasKev&resultsPerPage=2000` returns all 1,665 records in a single sub-second request.

## Consequences

- The full catalogue downloads in **12 seconds** instead of 12 hours; 116 MB across 28 annual files.
- Schema fidelity was verified rather than assumed, on CVE-2021-44228: `cisaExploitAdd`,
  `cisaActionDue`, `cisaRequiredAction`, `metrics.cvssMetricV31`, `metrics.cvssMetricV2`,
  `metrics.ssvcV203` and `weaknesses` all survive intact, identical to the API's own objects.
- A third party now sits between this project and its data. Mitigated by `MANIFEST.json`, which
  records the URL, size, SHA-256 and record count of every file used.
- Redistribution obliges a notice: the mirror "uses and redistributes data from the NVD API but is
  neither endorsed nor certified by the NVD". It appears in the README, in the app sidebar and in
  the manifest.

## Rejected

**The official API.** Twelve hours per refresh makes the pipeline unrunnable, and the silent hang
makes it unreliable even given the time. An API key would raise the rate limit but not fix the
stall, which is a transport problem rather than a quota one. The download watchdog in `src/ingest.py`
exists because of this failure and protects the mirror path too.
