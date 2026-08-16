"""Fetch the raw feeds and record exactly what was fetched.

The interesting part is the watchdog. An earlier attempt at this project pulled
the NVD through its official API and hung for 105 minutes on a single page: the
server kept the socket alive while dribbling bytes, so neither the connect nor
the read timeout ever fired. A read timeout answers "did anything arrive?"; the
question that matters is "is this actually getting anywhere?", which is a
question about throughput. :func:`download` asks that one.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import lzma
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

from src import paths, sources
from src.sources import Source

CHUNK = 1 << 16  # 64 KiB
PROGRESS_QUANTUM = 1 << 16  # bytes that must arrive to count as progress
STALL_SECONDS = 60.0
MAX_SECONDS = 600.0
ATTEMPTS = 5
CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 30.0


class StalledDownload(RuntimeError):
    """The transfer was alive but going nowhere."""


@dataclass(frozen=True)
class Fetched:
    """What ended up on disk, and what it was."""

    name: str
    url: str
    path: str
    bytes: int
    sha256: str
    records: int | None
    fetched_at: str


def _download_once(url: str, dest: Path) -> int:
    """Stream one attempt to ``dest``. Returns bytes written."""
    started = time.monotonic()
    last_progress = started
    since_progress = 0
    written = 0
    tmp = dest.with_suffix(dest.suffix + ".part")

    with requests.get(
        url, stream=True, allow_redirects=True, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)
    ) as response:
        response.raise_for_status()
        with tmp.open("wb") as handle:
            for chunk in response.iter_content(CHUNK):
                if not chunk:
                    continue
                handle.write(chunk)
                written += len(chunk)
                since_progress += len(chunk)
                now = time.monotonic()
                if since_progress >= PROGRESS_QUANTUM:
                    last_progress, since_progress = now, 0
                elif now - last_progress > STALL_SECONDS:
                    raise StalledDownload(
                        f"{url}: {written:,} bytes in {now - started:.0f}s, "
                        f"nothing meaningful for {now - last_progress:.0f}s"
                    )
                if now - started > MAX_SECONDS:
                    raise StalledDownload(f"{url}: exceeded {MAX_SECONDS:.0f}s")

    tmp.replace(dest)
    return written


def download(url: str, dest: Path, *, attempts: int = ATTEMPTS) -> int:
    """Fetch ``url`` to ``dest``, retrying on transport failures.

    Retries cover stalls, connection errors and 5xx. A 404 is not retried: the
    URL is wrong and waiting will not fix it.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, attempts + 1):
        try:
            return _download_once(url, dest)
        except requests.HTTPError as error:
            status = error.response.status_code if error.response is not None else 0
            if status < 500:
                raise
            last = error
        except (StalledDownload, requests.RequestException) as error:
            last = error
        if attempt < attempts:
            backoff = 2.0**attempt
            print(f"  retry {attempt}/{attempts - 1} in {backoff:.0f}s: {last}")
            time.sleep(backoff)
    raise RuntimeError(f"giving up on {url} after {attempts} attempts: {last}")


def count_records(path: Path) -> int | None:
    """How many records the file holds, so the manifest can prove what arrived.

    Returns ``None`` for shapes we do not know how to count rather than guessing.
    """
    name = path.name
    if name.endswith(".json"):
        payload = json.loads(path.read_text())
        if isinstance(payload, dict) and "vulnerabilities" in payload:
            return len(payload["vulnerabilities"])
        return None
    if name.endswith(".csv.gz"):
        with gzip.open(path, "rt") as handle:
            handle.readline()  # the comment line carrying model version
            handle.readline()  # the real header
            return sum(1 for _ in handle)
    if name.endswith(".json.xz"):
        # Reading the count without parsing 200 MB of CVEs: it sits in the first
        # few hundred bytes of the file.
        with lzma.open(path, "rt") as handle:
            head = handle.read(400)
        marker = '"cve_count":'
        start = head.find(marker)
        if start == -1:
            return None
        return int(head[start + len(marker) :].split(",")[0].strip())
    return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def describe(source: Source) -> Fetched:
    """Record what is on disk for ``source``."""
    return Fetched(
        name=source.name,
        url=source.url,
        path=str(source.dest.relative_to(paths.ROOT)),
        bytes=source.dest.stat().st_size,
        sha256=sha256(source.dest),
        records=count_records(source.dest),
        fetched_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def ingest(*, force: bool = False) -> list[Fetched]:
    """Fetch everything missing and write the manifest.

    Feeds move on. The manifest is what lets a later reader tell whether the
    numbers in the README came from the same bytes they are looking at, so it is
    committed even though the files it describes are not.
    """
    paths.ensure_dirs()
    records: list[Fetched] = []
    for source in sources.all_sources():
        if source.dest.exists() and not force:
            print(f"  have  {source.name}")
        else:
            print(f"  fetch {source.name} ... ", end="", flush=True)
            written = download(source.url, source.dest)
            print(f"{written / 1e6:.1f} MB")
        records.append(describe(source))

    paths.MANIFEST.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "notice": sources.NVD_MIRROR_NOTICE,
                "files": [asdict(record) for record in records],
            },
            indent=2,
        )
        + "\n"
    )
    total = sum(record.bytes for record in records)
    print(f"{len(records)} files, {total / 1e6:.0f} MB, manifest written")
    return records


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-fetch files already present")
    ingest(force=parser.parse_args().force)
