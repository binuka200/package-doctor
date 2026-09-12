#!/usr/bin/env python3
"""Scan PyPI at scale and write one row per package.

This is the research instrument rather than the product: it reuses the
scanner's own sources to build a dataset about the ecosystem, which is a
different job from telling one developer what to fix.

The question it exists to answer: **how often does a package with a published
advisory never receive a fix, and does that rate differ by what the package
does?** A six-project sample suggested the AI/ML ecosystem is several times
worse than everything else. That is a hypothesis at n=15, and this turns it
into a number or kills it.

Usage:
    python research/bulk_scan.py --top 3000 --out data/pypi.jsonl
    python research/bulk_scan.py --top 3000 --out data/pypi.jsonl --resume

Design notes:

* **Resumable.** A run over thousands of packages will be interrupted. Rows are
  appended as they complete and --resume skips names already present, so a
  restart costs nothing.
* **Polite.** Modest concurrency against free, unauthenticated services. The
  scanner's SQLite cache sits underneath, so a re-run is nearly free and does
  not re-ask anyone's API.
* **Reproducible.** Every row records the date it was collected, because
  advisory counts and repository state move.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from package_doctor.cache import Cache
from package_doctor.exposure import load_exposure_map
from package_doctor.sources.client import Client
from package_doctor.sources.ecosystems import EcosystemsSource
from package_doctor.sources.osv import OSVSource, build_history
from package_doctor.sources.pypi import (
    PyPISource,
    extract_github_repo,
    normalise,
)

TOP_PACKAGES = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


async def fetch_top(client: Client, limit: int) -> list[tuple[int, str, int]]:
    data = await client.get_json(TOP_PACKAGES, cache_key="research:top-pypi")
    rows = (data or {}).get("rows") or (data or {}).get("packages") or []
    out = []
    for rank, row in enumerate(rows[:limit], start=1):
        out.append((rank, row["project"], int(row.get("download_count") or 0)))
    return out


async def scan_one(
    sources: tuple[PyPISource, OSVSource, EcosystemsSource],
    exposure_map,
    rank: int,
    name: str,
    downloads: int,
    now: dt.datetime,
    with_repo: bool,
) -> dict:
    pypi, osv, repos = sources
    row: dict = {
        "rank": rank,
        "name": normalise(name),
        "downloads": downloads,
        "collected": now.date().isoformat(),
    }

    data, vulns = await asyncio.gather(pypi.fetch(name), osv.fetch(name))
    if data is None:
        row["error"] = "not on pypi"
        return row

    info = data.get("info") or {}
    releases = pypi.release_dates(data)
    latest, last_release = pypi.last_release(data)
    history = build_history(name, vulns, releases, None)

    exposure = exposure_map.lookup(name, info)
    row.update(
        {
            "latest_version": latest,
            "last_release": last_release.date().isoformat() if last_release else None,
            "days_since_release": (now - last_release).days if last_release else None,
            "release_count": len(releases),
            "inactive_classifier": pypi.has_inactive_classifier(data),
            "requires_python": info.get("requires_python"),
            # The curated category is the dimension the whole question turns on.
            "exposure": exposure.categories,
            "exposure_confidence": exposure.confidence.value,
            "reviewed": exposure_map.is_reviewed(name),
            "advisories_total": history.total,
            "advisories_unfixed": history.unfixed,
            "advisories_timely": history.timely,
            "advisories_late": history.late,
            "median_late_days": history.median_late_days,
            "advisories_undatable": history.unmatched,
        }
    )

    slug = extract_github_repo(info)
    row["repo"] = slug
    if slug and with_repo:
        repo = await repos.fetch_repo(slug)
        if repo.found:
            row["repo_archived"] = repo.archived
            row["repo_last_push"] = (
                repo.pushed_at.date().isoformat() if repo.pushed_at else None
            )
            row["repo_open_issues"] = repo.open_issues
        else:
            # Distinguish "no repository declared" from "we could not read it".
            row["repo_error"] = "metadata unavailable"
    return row


async def run(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    done: set[str] = set()
    if args.resume and out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["name"])
            except (json.JSONDecodeError, KeyError):
                continue
        print(f"resuming: {len(done)} rows already collected", file=sys.stderr)

    now = dt.datetime.now(dt.timezone.utc)
    cache = Cache(ttl=args.cache_ttl)
    exposure_map = load_exposure_map()

    try:
        async with Client(cache, concurrency=args.concurrency, timeout=30.0) as client:
            sources = (PyPISource(client), OSVSource(client), EcosystemsSource(client))
            targets = [
                (rank, name, downloads)
                for rank, name, downloads in await fetch_top(client, args.top)
                if normalise(name) not in done
            ]
            if not targets:
                print("nothing to do", file=sys.stderr)
                return 0
            print(f"scanning {len(targets)} packages -> {out}", file=sys.stderr)

            written = 0
            lock = asyncio.Lock()
            with out.open("a", encoding="utf-8") as fh:

                async def worker(rank: int, name: str, downloads: int) -> None:
                    nonlocal written
                    try:
                        row = await scan_one(
                            sources, exposure_map, rank, name, downloads, now,
                            with_repo=not args.no_repo,
                        )
                    except Exception as exc:
                        row = {"rank": rank, "name": normalise(name), "error": repr(exc)}
                    async with lock:
                        fh.write(json.dumps(row) + "\n")
                        fh.flush()
                        written += 1
                        if written % 50 == 0:
                            print(
                                f"  {written}/{len(targets)}", file=sys.stderr, flush=True
                            )

                # Batched rather than one enormous gather, so memory stays flat
                # and an interrupt loses at most one batch.
                batch = args.concurrency * 4
                for start in range(0, len(targets), batch):
                    chunk = targets[start : start + batch]
                    await asyncio.gather(*(worker(*t) for t in chunk))
    finally:
        cache.close()

    print(f"done: {written} rows appended to {out}", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--top", type=int, default=1000, help="how many top packages (default 1000)")
    p.add_argument("--out", default="data/pypi.jsonl", help="JSONL output path")
    p.add_argument("--resume", action="store_true", help="skip names already in --out")
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--cache-ttl", type=int, default=7 * 24 * 3600)
    p.add_argument("--no-repo", action="store_true", help="skip repository lookups (faster)")
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
