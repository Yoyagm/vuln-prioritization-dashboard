"""Join the three feeds into the one table everything downstream reads.

The join keys are trivially clean -- every KEV id exists in the NVD, every NVD
id has an EPSS score -- but that is a fact about today's snapshot, not a
guarantee, so the merges stay left joins and the nullability rules live in the
schema tests.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pandas as pd
import pyarrow as pa

from src import extract, paths

CATEGORICAL = ("vuln_status", "cvss_severity", "cvss_version", "ssvc_exploitation")
DATE = pd.ArrowDtype(pa.date32())

# NVD's status for a withdrawn identifier. These are not vulnerabilities and
# counting them would inflate every denominator in the analysis.
REJECTED = "Rejected"


def load_kev(path: Path | None = None) -> pd.DataFrame:
    """CISA's catalogue, as one row per exploited CVE."""
    payload = json.loads((path or paths.KEV_JSON).read_text())
    frame = pd.DataFrame(payload["vulnerabilities"])
    frame = frame.rename(
        columns={
            "cveID": "cve_id",
            "dateAdded": "kev_date_added",
            "dueDate": "kev_due_date",
            "vendorProject": "kev_vendor",
            "product": "kev_product",
        }
    )
    # The feed spells this "Known" / "Unknown" rather than using a boolean.
    frame["kev_ransomware"] = frame["knownRansomwareCampaignUse"].eq("Known")
    for column in ("kev_date_added", "kev_due_date"):
        frame[column] = pd.to_datetime(frame[column]).astype(DATE)
    return frame[
        [
            "cve_id",
            "kev_date_added",
            "kev_due_date",
            "kev_ransomware",
            "kev_vendor",
            "kev_product",
        ]
    ]


def load_epss(path: Path | None = None) -> pd.DataFrame:
    """One EPSS dump.

    Line 1 is a comment holding the model version and score date; the header is
    line 2. Reading it without skipping that line yields a one-column frame and
    a very confusing afternoon.
    """
    path = path or paths.EPSS_CURRENT
    with gzip.open(path, "rt") as handle:
        handle.readline()
        frame = pd.read_csv(handle)
    return frame.rename(
        columns={"cve": "cve_id", "epss": "epss", "percentile": "epss_percentile"}
    )


def epss_metadata(path: Path | None = None) -> dict[str, str]:
    """The model version and score date from the comment line."""
    path = path or paths.EPSS_CURRENT
    with gzip.open(path, "rt") as handle:
        comment = handle.readline().strip().lstrip("#")
    return dict(
        part.split(":", 1) for part in comment.split(",") if ":" in part
    )


def build(
    *,
    nvd_dir: Path | None = None,
    kev_path: Path | None = None,
    epss_path: Path | None = None,
    verbose: bool = False,
) -> pd.DataFrame:
    """The joined table, ready to be written."""
    frame = extract.extract_all(nvd_dir, verbose=verbose)
    total = len(frame)
    frame = frame[frame["vuln_status"] != REJECTED].copy()
    if verbose:
        print(f"  {total:,} CVEs, {total - len(frame):,} rejected dropped")

    kev = load_kev(kev_path)
    epss = load_epss(epss_path)[["cve_id", "epss", "epss_percentile"]]

    frame = frame.merge(kev, on="cve_id", how="left").merge(epss, on="cve_id", how="left")
    frame["in_kev"] = frame["cve_id"].isin(set(kev["cve_id"]))
    frame["kev_ransomware"] = frame["kev_ransomware"].fillna(False).astype(bool)

    for column in CATEGORICAL:
        frame[column] = frame[column].astype("category")
    for column in ("cvss_base", "epss", "epss_percentile"):
        frame[column] = frame[column].astype("float32")

    return frame[
        [
            "cve_id",
            "published",
            "vuln_status",
            "cvss_base",
            "cvss_severity",
            "cvss_version",
            "epss",
            "epss_percentile",
            "in_kev",
            "kev_date_added",
            "kev_due_date",
            "kev_ransomware",
            "kev_vendor",
            "kev_product",
            "ssvc_exploitation",
            "cwe_ids",
        ]
    ].reset_index(drop=True)


def write(frame: pd.DataFrame, path: Path | None = None) -> Path:
    path = path or paths.VULNERABILITIES
    path.parent.mkdir(parents=True, exist_ok=True)
    # zstd over the default snappy: same read speed, roughly a third smaller,
    # and this file is committed so its size is a repo-wide cost.
    frame.to_parquet(path, index=False, compression="zstd")
    return path


if __name__ == "__main__":
    table = build(verbose=True)
    destination = write(table)
    print(
        f"{len(table):,} rows -> {destination.relative_to(paths.ROOT)} "
        f"({destination.stat().st_size / 1e6:.1f} MB), "
        f"{int(table['in_kev'].sum()):,} in KEV"
    )
