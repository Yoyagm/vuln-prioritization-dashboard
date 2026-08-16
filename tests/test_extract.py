"""Which CVSS score gets believed, and what happens when there isn't one."""

from __future__ import annotations

import pytest

from src import extract

NVD = extract.NVD_SOURCE


def metric(source: str, kind: str, score: float) -> dict:
    return {
        "source": source,
        "type": kind,
        "cvssData": {"baseScore": score, "baseSeverity": "HIGH", "version": "3.1"},
    }


def test_nvd_primary_wins_over_a_vendor_primary():
    entries = [metric("vendor@example.com", "Primary", 4.0), metric(NVD, "Primary", 9.8)]
    assert extract.pick_metric(entries)["cvssData"]["baseScore"] == 9.8


def test_a_primary_wins_over_a_secondary():
    entries = [metric("vendor@example.com", "Secondary", 4.0), metric("other", "Primary", 7.5)]
    assert extract.pick_metric(entries)["cvssData"]["baseScore"] == 7.5


def test_first_entry_is_used_when_nothing_is_primary():
    entries = [metric("a", "Secondary", 3.0), metric("b", "Secondary", 8.0)]
    assert extract.pick_metric(entries)["cvssData"]["baseScore"] == 3.0


def test_no_metrics_yields_no_score():
    assert extract.pick_metric([]) is None
    assert extract.pick_metric(None) is None


def test_newer_scoring_system_wins():
    item = {
        "id": "CVE-0000-0001",
        "metrics": {
            "cvssMetricV2": [metric(NVD, "Primary", 5.0)],
            "cvssMetricV31": [metric(NVD, "Primary", 9.1)],
        },
    }
    row = extract.extract_cve(item)
    assert (row["cvss_base"], row["cvss_version"]) == (9.1, "3.1")


def test_v2_only_cve_still_gets_a_score_and_says_so():
    item = {"id": "CVE-0000-0002", "metrics": {"cvssMetricV2": [metric(NVD, "Primary", 5.0)]}}
    row = extract.extract_cve(item)
    assert (row["cvss_base"], row["cvss_version"]) == (5.0, "2.0")


def test_a_metric_without_a_base_score_falls_through_to_the_next_version():
    item = {
        "id": "CVE-0000-0003",
        "metrics": {
            "cvssMetricV31": [{"source": NVD, "type": "Primary", "cvssData": {}}],
            "cvssMetricV2": [metric(NVD, "Primary", 6.4)],
        },
    }
    row = extract.extract_cve(item)
    assert (row["cvss_base"], row["cvss_version"]) == (6.4, "2.0")


def test_cve_with_no_metrics_at_all_is_null_everywhere():
    row = extract.extract_cve({"id": "CVE-0000-0004", "metrics": {}})
    assert row["cvss_base"] is None
    assert row["cvss_severity"] is None
    assert row["cvss_version"] is None


def test_cwes_are_deduplicated_and_placeholders_dropped():
    item = {
        "id": "CVE-0000-0005",
        "weaknesses": [
            {"description": [{"value": "CWE-20"}, {"value": "CWE-79"}]},
            {"description": [{"value": "CWE-20"}, {"value": "NVD-CWE-noinfo"}]},
        ],
    }
    assert extract.extract_cve(item)["cwe_ids"] == ["CWE-20", "CWE-79"]


def test_ssvc_exploitation_is_pulled_out_of_its_options_list():
    item = {
        "id": "CVE-0000-0006",
        "metrics": {
            "ssvcV203": [
                {
                    "source": "cisa",
                    "ssvcData": {
                        "options": [
                            {"automatable": "no"},
                            {"exploitation": "active"},
                        ]
                    },
                }
            ]
        },
    }
    assert extract.extract_cve(item)["ssvc_exploitation"] == "active"


def test_real_fixtures_cover_every_branch(fixture_items):
    """The fixture must keep exercising the shapes these tests care about."""
    rows = [extract.extract_cve(item) for item in fixture_items]
    assert any(row["cvss_base"] is None for row in rows), "no CVE without a score"
    assert any(row["cvss_version"] == "2.0" for row in rows), "no v2-only CVE"
    assert any(row["ssvc_exploitation"] for row in rows), "no CVE carrying SSVC"
    assert any(row["cwe_ids"] for row in rows), "no CVE carrying a CWE"
    assert any(item.get("vulnStatus") == "Rejected" for item in fixture_items)


def test_extract_all_reads_the_fixture_feed(nvd_dir, fixture_items):
    frame = extract.extract_all(nvd_dir)
    # Counted against the fixture itself rather than a hard-coded number, so
    # regenerating the fixture does not require editing this test.
    assert len(frame) == len(fixture_items)
    assert frame["cve_id"].is_unique
    assert frame["published"].notna().all()


def test_missing_feed_directory_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="make ingest"):
        extract.extract_all(tmp_path)
