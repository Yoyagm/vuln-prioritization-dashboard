"""Carve test fixtures out of the real feeds.

Fixtures are real payloads, trimmed -- not hand-written ones. Hand-written
fixtures encode what you believe the format is, which is exactly the belief the
tests are supposed to be checking. Each one is picked because it exercises a
branch: a CVE with no score at all, a rejected identifier, a KEV entry used in
ransomware, a CVE carrying only a v2 score, one carrying CISA's SSVC decision,
and one whose scores come from a vendor rather than from NVD.

Run after `make ingest` when a feed's shape changes. Output is committed.
"""

from __future__ import annotations

import gzip
import json
import lzma

from src import extract, paths

FIXTURES = paths.ROOT / "tests" / "fixtures"
# 2010 is not optional: CVSS v2 was retired around 2016, so a CVE scored only on
# v2 -- a branch the extractor has to handle -- exists nowhere in recent years.
YEARS = (2010, 2021, 2024, 2026)
PER_BRANCH = 3


def branches(item: dict) -> set[str]:
    """Every branch this CVE exercises. One CVE can serve several."""
    metrics = item.get("metrics") or {}
    found: set[str] = set()
    if item.get("vulnStatus") == "Rejected":
        found.add("rejected")
    present = [key for key, _ in extract.CVSS_KEYS if metrics.get(key)]
    if not present:
        found.add("no_cvss")
    elif present == ["cvssMetricV2"]:
        # Only v2 present. Checking just V31/V40 would also match a CVE carrying
        # a v3.0 score, which extracts as 3.0 and would make the fixture lie.
        found.add("v2_only")
    if metrics.get("ssvcV203"):
        found.add("ssvc")
    entries = metrics.get("cvssMetricV31") or []
    if entries and not any(
        e.get("type") == "Primary" and e.get("source") == extract.NVD_SOURCE for e in entries
    ):
        found.add("secondary_only")
    if item.get("cisaExploitAdd"):
        found.add("kev")
    return found


REQUIRED = {"rejected", "no_cvss", "v2_only", "ssvc", "secondary_only", "kev"}


def build_nvd_fixture() -> set[str]:
    """One trimmed annual feed holding a few of each interesting shape."""
    wanted: dict[str, list[dict]] = {}
    for year in YEARS:
        with lzma.open(paths.NVD_ANNUAL / f"CVE-{year}.json.xz", "rt") as handle:
            payload = json.load(handle)
        for item in payload["cve_items"]:
            for branch in branches(item):
                bucket = wanted.setdefault(branch, [])
                if len(bucket) < PER_BRANCH:
                    bucket.append(item)

    missing = REQUIRED - set(wanted)
    if missing:
        raise RuntimeError(f"no example found for {sorted(missing)} -- fixture would be blind")

    seen: set[str] = set()
    items = []
    for branch in sorted(wanted):
        for item in wanted[branch]:
            if item["id"] not in seen:
                seen.add(item["id"])
                items.append(item)
    items.sort(key=lambda item: item["id"])
    fixture = {
        "timestamp": "2026-08-15T00:00:00+00:00",
        "cve_count": len(items),
        "feed_name": "CVE-fixture",
        "source": "trimmed from fkie-cad/nvd-json-data-feeds",
        "cve_items": items,
    }
    destination = FIXTURES / "nvd" / "CVE-1999.json.xz"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with lzma.open(destination, "wt") as handle:
        json.dump(fixture, handle)
    print(f"nvd fixture: {len(items)} CVEs, branches {sorted(wanted)}")
    return {item["id"] for item in items}


def build_kev_fixture(ids: set[str]) -> None:
    """KEV entries for the fixture CVEs, plus one id absent from the NVD side."""
    payload = json.loads(paths.KEV_JSON.read_text())
    entries = [v for v in payload["vulnerabilities"] if v["cveID"] in ids]
    ransomware = next(
        v for v in payload["vulnerabilities"] if v["knownRansomwareCampaignUse"] == "Known"
    )
    if ransomware["cveID"] not in ids:
        entries.append(ransomware)
    orphan = dict(entries[0])
    orphan["cveID"] = "CVE-1999-99999"  # in KEV, unknown to the NVD: must not crash
    entries.append(orphan)
    (FIXTURES / "kev.json").write_text(
        json.dumps(
            {
                "title": "fixture",
                "catalogVersion": "2026.08.14",
                "dateReleased": "2026-08-14T16:34:49.0391Z",
                "count": len(entries),
                "vulnerabilities": entries,
            },
            indent=1,
        )
    )
    print(f"kev fixture: {len(entries)} entries")


def build_epss_fixture(ids: set[str]) -> None:
    """EPSS rows for most of the fixture CVEs -- one is left out on purpose."""
    keep = sorted(ids)[:-1]
    lines = ["#model_version:v2026.06.15,score_date:2026-08-15T12:02:44Z", "cve,epss,percentile"]
    for index, cve in enumerate(keep):
        score = round(0.9 - index * 0.02, 5)
        lines.append(f"{cve},{max(score, 0.00001):.5f},{max(0.999 - index * 0.01, 0.001):.5f}")
    with gzip.open(FIXTURES / "epss.csv.gz", "wt") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"epss fixture: {len(keep)} rows, 1 CVE deliberately missing")


if __name__ == "__main__":
    FIXTURES.mkdir(parents=True, exist_ok=True)
    fixture_ids = build_nvd_fixture()
    build_kev_fixture(fixture_ids)
    build_epss_fixture(fixture_ids)
