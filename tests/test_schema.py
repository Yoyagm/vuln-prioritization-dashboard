"""The data contract of §3.2, asserted column by column.

Downstream code and every published figure assume this shape. If it drifts, it
should break here rather than quietly change a number in the README.
"""

from __future__ import annotations

import pandas as pd
import pyarrow.parquet as pq
import pytest

from src import build, paths

EXPECTED_COLUMNS = [
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

SIZE_BUDGET_MB = 12


def test_columns_are_exactly_the_contract(joined):
    assert list(joined.columns) == EXPECTED_COLUMNS


def test_dtypes_match_the_contract(joined):
    assert joined["cvss_base"].dtype == "float32"
    assert joined["epss"].dtype == "float32"
    assert joined["epss_percentile"].dtype == "float32"
    assert joined["in_kev"].dtype == "bool"
    assert joined["kev_ransomware"].dtype == "bool"
    assert isinstance(joined["vuln_status"].dtype, pd.CategoricalDtype)
    assert isinstance(joined["cvss_severity"].dtype, pd.CategoricalDtype)
    assert str(joined["kev_date_added"].dtype) == "date32[day][pyarrow]"


def test_primary_key_is_unique_and_never_null(joined):
    assert joined["cve_id"].is_unique
    assert joined["cve_id"].notna().all()


def test_rejected_cves_never_survive(joined):
    assert (joined["vuln_status"] != build.REJECTED).all()


def test_kev_columns_are_null_exactly_when_not_in_kev(joined):
    outside = joined[~joined["in_kev"]]
    inside = joined[joined["in_kev"]]
    assert outside["kev_date_added"].isna().all()
    assert outside["kev_due_date"].isna().all()
    assert outside["kev_vendor"].isna().all()
    assert inside["kev_date_added"].notna().all()
    assert inside["kev_due_date"].notna().all()


def test_ransomware_is_false_rather_than_null_outside_kev(joined):
    assert not joined.loc[~joined["in_kev"], "kev_ransomware"].any()


def test_severity_is_present_exactly_when_a_score_is(joined):
    scored = joined["cvss_base"].notna()
    assert joined.loc[scored, "cvss_version"].notna().all()
    assert joined.loc[~scored, "cvss_version"].isna().all()


def test_scores_stay_inside_their_ranges(joined):
    scores = joined["cvss_base"].dropna()
    assert scores.between(0.0, 10.0).all()
    epss = joined["epss"].dropna()
    assert epss.between(0.0, 1.0).all()


def test_a_kev_id_absent_from_the_nvd_is_dropped_not_crashed(joined, kev_path):
    """The fixture KEV holds CVE-1999-99999, which no feed knows about."""
    import json

    ids = {v["cveID"] for v in json.loads(kev_path.read_text())["vulnerabilities"]}
    assert "CVE-1999-99999" in ids
    assert "CVE-1999-99999" not in set(joined["cve_id"])


def test_a_cve_with_no_epss_row_survives_with_a_null(joined):
    """One fixture CVE is deliberately absent from the EPSS dump."""
    assert joined["epss"].isna().sum() == 1


def test_epss_metadata_is_read_from_the_comment_line(epss_path):
    meta = build.epss_metadata(epss_path)
    assert meta["model_version"] == "v2026.06.15"
    assert meta["score_date"].startswith("2026-08-15")


@pytest.mark.skipif(not paths.VULNERABILITIES.exists(), reason="artefact not built")
class TestCommittedArtefact:
    """The real file, not the fixture: what actually ships in the repo."""

    def test_size_is_within_budget(self):
        size_mb = paths.VULNERABILITIES.stat().st_size / 1e6
        assert size_mb <= SIZE_BUDGET_MB, f"{size_mb:.1f} MB exceeds {SIZE_BUDGET_MB} MB"

    def test_shape_matches_the_contract(self):
        schema = pq.read_schema(paths.VULNERABILITIES)
        assert schema.names == EXPECTED_COLUMNS
        assert str(schema.field("kev_date_added").type) == "date32[day]"
        assert str(schema.field("cwe_ids").type) == "list<element: string>"

    def test_row_count_is_the_full_live_catalogue(self):
        frame = pd.read_parquet(paths.VULNERABILITIES, columns=["cve_id", "in_kev"])
        assert len(frame) > 350_000
        assert frame["cve_id"].is_unique
        assert 1_000 < int(frame["in_kev"].sum()) < 5_000


# Measured, not wished for. The observed peak is 3.5-4.8 GB across identical
# runs -- allocator variance, not code -- with the floor set by one year's
# json.load at 1.84 GB. The budget sits above that spread, and far below what
# loading the 3 GB combined file would cost. That regression, someone deciding
# CVE-all.json.xz is simpler, is what this test actually guards; it is not a
# tripwire for a few hundred megabytes of drift.
RSS_BUDGET_GB = 6.0


@pytest.mark.slow
@pytest.mark.skipif(
    len(list(paths.NVD_ANNUAL.glob("CVE-*.json.xz"))) < 20,
    reason="raw annual feeds not present -- run `make ingest`",
)
def test_the_full_extract_stays_inside_its_memory_budget():
    """The reason the parse goes year by year, asserted rather than assumed.

    Run in a subprocess so the measurement is of the extract alone, and so a
    regression that loads the 3 GB combined file fails here instead of taking
    the developer's machine down with it.
    """
    import subprocess
    import sys

    # The child reports its own high-water mark. Reading RUSAGE_CHILDREN from
    # here would give the maximum across every child the test session has ever
    # reaped, so the same code passed or failed depending on which other tests
    # had run first.
    probe = (
        "import resource, sys;"
        "from src import extract;"
        "n = len(extract.extract_all());"
        "peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;"
        "scale = 1e9 if sys.platform == 'darwin' else 1e6;"  # bytes vs kibibytes
        "print(n, peak / scale)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=paths.ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    rows, peak_gb = completed.stdout.split()

    assert int(rows) > 350_000
    assert float(peak_gb) < RSS_BUDGET_GB, (
        f"peak RSS {float(peak_gb):.2f} GB exceeds {RSS_BUDGET_GB} GB"
    )
