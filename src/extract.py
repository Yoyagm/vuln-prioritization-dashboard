"""Turn the NVD's annual JSON feeds into one slim table.

Two things here are load-bearing.

The first is memory. The full catalogue is 3 GB expanded, which does not fit
comfortably anywhere; one year is 200 MB and parses in under two seconds. So the
files are walked one year at a time and only the columns we need survive.

The second is :func:`pick_metric`. A CVE can carry several CVSS scores from
several scorers, and picking a different one silently changes every number in
this project. The rule is written once, here, and tested.
"""

from __future__ import annotations

import json
import lzma
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pandas as pd

from src import paths, sources

# Newest scoring system first: a CVE that has a v4.0 score gets scored on v4.0.
# Which one was used ends up in a column rather than being silently mixed.
CVSS_KEYS: tuple[tuple[str, str], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

NVD_SOURCE = "nvd@nist.gov"


def pick_metric(entries: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Choose which scorer to believe when a CVE carries several.

    NVD's own primary assessment wins; failing that any primary one; failing
    that the first entry, so a CVE scored only by its vendor still gets a score.
    """
    if not entries:
        return None
    for entry in entries:
        if entry.get("type") == "Primary" and entry.get("source") == NVD_SOURCE:
            return entry
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0]


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key, version in CVSS_KEYS:
        entry = pick_metric(metrics.get(key))
        if entry is None:
            continue
        data = entry.get("cvssData", {})
        base = data.get("baseScore")
        if base is None:
            continue
        # v2 puts severity beside cvssData rather than inside it.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return float(base), severity, version
    return None, None, None


def _ssvc_exploitation(metrics: dict[str, Any]) -> str | None:
    """CISA's own exploitation call, when it has made one."""
    entry = pick_metric(metrics.get("ssvcV203"))
    if entry is None:
        return None
    for option in entry.get("ssvcData", {}).get("options", []):
        if "exploitation" in option:
            return option["exploitation"]
    return None


def _cwe_ids(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    """De-duplicated CWE identifiers, ignoring NVD's placeholder values."""
    found: set[str] = set()
    for weakness in weaknesses or []:
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-") and value[4:].isdigit():
                found.add(value)
    return sorted(found)


def extract_cve(item: dict[str, Any]) -> dict[str, Any]:
    """One CVE record, reduced to the columns the dashboard needs."""
    metrics = item.get("metrics") or {}
    base, severity, version = _cvss(metrics)
    return {
        "cve_id": item["id"],
        "published": item.get("published"),
        "vuln_status": item.get("vulnStatus"),
        "cvss_base": base,
        "cvss_severity": severity,
        "cvss_version": version,
        "ssvc_exploitation": _ssvc_exploitation(metrics),
        "cwe_ids": _cwe_ids(item.get("weaknesses")),
    }


def iter_year(path: Path) -> Iterator[dict[str, Any]]:
    """Yield extracted records from one annual feed file."""
    with lzma.open(path, "rt") as handle:
        payload = json.load(handle)
    for item in payload["cve_items"]:
        yield extract_cve(item)


def annual_files(directory: Path | None = None) -> list[Path]:
    directory = directory or paths.NVD_ANNUAL
    return sorted(
        directory / f"CVE-{year}.json.xz"
        for year in range(sources.NVD_FIRST_YEAR, sources.NVD_LAST_YEAR + 1)
        if (directory / f"CVE-{year}.json.xz").exists()
    )


def extract_all(directory: Path | None = None, *, verbose: bool = False) -> pd.DataFrame:
    """Every CVE in the mirror, one row each.

    Memory here was measured rather than reasoned about. One year's ``json.load``
    alone costs **1.84 GB** for the 45,145 CVEs of 2025, because each parsed CVE
    drags along its ``configurations``, ``references`` and ``descriptions`` --
    all of which this function throws away. That is what makes walking the files
    one year at a time necessary; the combined file would be that cost many times
    over.

    The whole walk peaks between **3.5 and 4.8 GB**, and that spread is run-to-run
    variance on identical code, not a property of any particular version: an
    earlier round of "optimisation" here was comparing allocator noise. Building
    one DataFrame per year and concatenating was tried and is not measurably
    better, so the simpler version stayed.

    Cutting the floor properly means parsing the JSON incrementally rather than
    whole. That is a real option (``ijson``) and deliberately not taken: this
    runs offline on a laptop, not in the deployed app.
    """
    files = annual_files(directory)
    if not files:
        raise FileNotFoundError(
            f"no annual feeds in {directory or paths.NVD_ANNUAL} -- run `make ingest` first"
        )
    rows: list[dict[str, Any]] = []
    for path in files:
        before = len(rows)
        rows.extend(iter_year(path))
        if verbose:
            print(f"  {path.name:22s} {len(rows) - before:>7,}")
    frame = pd.DataFrame(rows)
    # Nothing needs the dicts once the frame exists, and they are the single
    # largest thing alive at this point.
    del rows
    frame["published"] = pd.to_datetime(frame["published"], format="ISO8601")
    return frame


if __name__ == "__main__":
    table = extract_all(verbose=True)
    print(f"{len(table):,} CVEs")
