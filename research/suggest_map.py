#!/usr/bin/env python3
"""Which packages should the exposure map have an opinion about next?

Curating by working down a download list is brute force: most of what you read
does not belong in the map, and the entries that matter are scattered. This
inverts it. Every package the map has no opinion about is scored by how much
that silence costs, and you review the top of the list.

The scoring is deliberately about *cost of not knowing*, not about how likely
something is to be exposed:

* **Unfixed advisories** weigh most. If such a package turns out to sit at a
  trust boundary, it is dangerous right now and the map is hiding it. If it
  turns out not to, the entry is still worth having, because it stops the same
  question being asked again.
* **Advisories against a pinned version** come next - a live finding being
  under-prioritised.
* **Any advisory history at all** is weak evidence of attack surface: code
  nobody can reach rarely accumulates CVEs.
* **Downloads** break ties. A judgement about a package in ten thousand
  projects is worth more than one about a package in three.

Each candidate is printed with what it actually does, because the friction in
this job is never the decision - it is looking up what the package is for.

Usage:
    package-doctor scan . --json -o scan.json
    python research/suggest_map.py --scan scan.json

    python research/suggest_map.py --dataset data/pypi-top3000.jsonl --limit 30
    python research/suggest_map.py --dataset data/pypi-top3000.jsonl --emit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from package_doctor.cache import Cache  # noqa: E402
from package_doctor.exposure import load_exposure_map  # noqa: E402
from package_doctor.sources.client import Client  # noqa: E402
from package_doctor.sources.pypi import PyPISource, normalise  # noqa: E402

CATEGORIES = (
    "auth", "crypto", "deserialization", "ml_model", "llm_agent", "markup",
    "templating", "url", "http", "framework", "query", "archive", "filetype",
    "remote_exec",
)


@dataclass
class Candidate:
    name: str
    unfixed: int = 0
    affecting: int = 0
    advisories: int = 0
    downloads: int = 0
    archived: bool = False
    stale_days: int | None = None
    summary: str = ""
    seen_in: str = ""

    @property
    def score(self) -> tuple:
        # Ordering only - the numbers below are ranks, not measurements, and
        # nothing downstream treats them as a probability of anything.
        return (
            -self.unfixed,
            -self.affecting,
            -(1 if self.archived else 0),
            -self.advisories,
            -self.downloads,
            self.name,
        )

    @property
    def why(self) -> str:
        bits = []
        if self.unfixed:
            bits.append(f"{self.unfixed} advisor{'y' if self.unfixed == 1 else 'ies'} never fixed")
        if self.affecting:
            bits.append(f"{self.affecting} affect the pinned version")
        if self.archived:
            bits.append("repository archived")
        if not bits and self.advisories:
            bits.append(f"{self.advisories} past advisories")
        if not bits and self.stale_days and self.stale_days > 730:
            bits.append(f"no release in {self.stale_days / 365.25:.1f}y")
        return "; ".join(bits) or "no signal"


def from_scan(path: Path) -> list[Candidate]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for row in data.get("findings", []):
        if row.get("exposure", {}).get("confidence") == "curated":
            continue
        adv = row.get("remediation", {}).get("advisories", {})
        out.append(
            Candidate(
                name=normalise(row["name"]),
                unfixed=adv.get("unfixed") or 0,
                affecting=adv.get("affecting_current") or 0,
                advisories=adv.get("total") or 0,
                archived=bool(row.get("remediation", {}).get("repo_archived")),
                seen_in=path.stem,
            )
        )
    return out


def from_dataset(path: Path) -> list[Candidate]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in row or row.get("exposure_confidence") == "curated":
            continue
        out.append(
            Candidate(
                name=normalise(row["name"]),
                unfixed=row.get("advisories_unfixed") or 0,
                advisories=row.get("advisories_total") or 0,
                downloads=row.get("downloads") or 0,
                archived=bool(row.get("repo_archived")),
                stale_days=row.get("days_since_release"),
                seen_in="dataset",
            )
        )
    return out


async def add_summaries(candidates: list[Candidate]) -> None:
    """Fetch what each package is for. This is the whole point of the tool."""
    cache = Cache(ttl=7 * 24 * 3600)
    try:
        async with Client(cache, concurrency=8) as client:
            pypi = PyPISource(client)

            async def one(c: Candidate) -> None:
                data = await pypi.fetch(c.name)
                if data:
                    c.summary = ((data.get("info") or {}).get("summary") or "").strip()

            await asyncio.gather(*(one(c) for c in candidates))
    finally:
        cache.close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--scan", type=Path, help="JSON from `package-doctor scan --json`")
    src.add_argument("--dataset", type=Path, help="JSONL from research/bulk_scan.py")
    p.add_argument("--limit", type=int, default=25, help="how many to review (default 25)")
    p.add_argument("--emit", action="store_true",
                   help="print pasteable TOML stubs instead of a review list")
    p.add_argument("--all", action="store_true",
                   help="include candidates with no signal at all")
    args = p.parse_args()

    candidates = from_scan(args.scan) if args.scan else from_dataset(args.dataset)

    # Never re-ask about something already decided, in any of the three lists.
    exposure_map = load_exposure_map()
    candidates = [c for c in candidates if not exposure_map.is_reviewed(c.name)]
    if not args.all:
        candidates = [
            c for c in candidates
            if c.unfixed or c.affecting or c.archived or c.advisories
            or (c.stale_days or 0) > 730
        ]
    if not candidates:
        print("Nothing worth reviewing: every package with a signal already has "
              "an entry.")
        return 0

    candidates.sort(key=lambda c: c.score)
    shortlist = candidates[: args.limit]
    asyncio.run(add_summaries(shortlist))

    if args.emit:
        print("# Paste each name under the right category, or under [reviewed]")
        print("# not_exposed with a note saying why the obvious guess is wrong.\n")
        for c in shortlist:
            print(f'  "{c.name}",  # {c.summary[:70] or "?"}')
        return 0

    print(f"{len(candidates)} packages have no entry and show some signal. "
          f"Top {len(shortlist)}:\n")
    for i, c in enumerate(shortlist, 1):
        print(f"{i:>3}. {c.name}")
        print(f"     {c.why}")
        if c.summary:
            print(f"     \"{c.summary[:88]}\"")
        print(f"     https://pypi.org/project/{c.name}/")
        print()
    print("For each: does it routinely handle data a stranger sent you?")
    print(f"  yes -> add to one of: {', '.join(CATEGORIES)}")
    print("  no  -> add to [reviewed] not_exposed, with the reason")
    print(f"\nFile: src/package_doctor/data/exposure.toml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
