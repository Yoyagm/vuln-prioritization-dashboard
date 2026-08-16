"""Where the data comes from, and the quirks of getting it.

Each quirk here cost real time to find, so it is written down next to the URL it
belongs to rather than discovered again.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src import paths

# CISA's catalogue of vulnerabilities it has confirmed exploited in the wild.
# One request, no auth, ~1.5 MB.
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# FIRST's daily EPSS dump. Two traps: the URL answers 302 so redirects must be
# followed, and line 1 is a comment carrying the model version and score date --
# the real header is line 2.
EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_SNAPSHOT_URL = "https://epss.empiricalsecurity.com/epss_scores-{cutoff}.csv.gz"

# The NVD's own API cannot serve the full catalogue: 189 pages at a measured
# 255 s/page, on a connection that dribbles bytes so socket timeouts never fire.
# This community mirror serves the same schema as one file per year, rebuilt
# daily. The /latest/download/ path is stable across the daily tags.
NVD_MIRROR_URL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    "CVE-{year}.json.xz"
)

# Redistributing the mirror obliges us to carry this. It belongs in the README.
NVD_MIRROR_NOTICE = (
    "This project uses data from the fkie-cad/nvd-json-data-feeds mirror, which "
    "uses and redistributes data from the NVD API but is neither endorsed nor "
    "certified by the NVD."
)

NVD_FIRST_YEAR = 1999
NVD_LAST_YEAR = 2026

# Frozen EPSS dates for the prospective evaluation. Six-month spacing: close
# enough together to show the result is not a fluke of one date, far enough back
# that each has accumulated enough newly-exploited CVEs to measure.
CUTOFFS = (
    "2023-08-15",
    "2024-02-15",
    "2024-08-15",
    "2025-02-15",
    "2025-08-15",
)


@dataclass(frozen=True)
class Source:
    """One downloadable file."""

    name: str
    url: str
    dest: Path


def all_sources() -> list[Source]:
    """Every file the pipeline needs, in the order it makes sense to fetch them."""
    sources = [
        Source("kev", KEV_URL, paths.KEV_JSON),
        Source("epss-current", EPSS_CURRENT_URL, paths.EPSS_CURRENT),
    ]
    sources += [
        Source(
            f"epss-{cutoff}",
            EPSS_SNAPSHOT_URL.format(cutoff=cutoff),
            paths.epss_snapshot(cutoff),
        )
        for cutoff in CUTOFFS
    ]
    sources += [
        Source(
            f"nvd-{year}",
            NVD_MIRROR_URL.format(year=year),
            paths.NVD_ANNUAL / f"CVE-{year}.json.xz",
        )
        for year in range(NVD_FIRST_YEAR, NVD_LAST_YEAR + 1)
    ]
    return sources
