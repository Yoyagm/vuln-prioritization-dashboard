"""Repo-relative paths.

Everything resolves from this file's location so the pipeline runs the same from
any working directory, and so a clean clone needs no configuration.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DATA = ROOT / "data"
RAW = DATA / "raw"
PROCESSED = DATA / "processed"

NVD_ANNUAL = RAW / "nvd-annual"
KEV_JSON = RAW / "kev.json"
EPSS_CURRENT = RAW / "epss_scores-current.csv.gz"
MANIFEST = RAW / "MANIFEST.json"

VULNERABILITIES = PROCESSED / "vulnerabilities.parquet"
ANALYSIS = PROCESSED / "analysis.json"

DOCS = ROOT / "docs"
IMG = DOCS / "img"


def epss_snapshot(cutoff: str) -> Path:
    """Path to a frozen EPSS dump, e.g. ``epss_2025-08-15.csv.gz``."""
    return RAW / f"epss_{cutoff}.csv.gz"


def ensure_dirs() -> None:
    for path in (RAW, PROCESSED, NVD_ANNUAL, IMG):
        path.mkdir(parents=True, exist_ok=True)
