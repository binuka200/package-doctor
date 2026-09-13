#!/usr/bin/env python3
"""Which packages should the exposure map have an opinion about next?

Curating by working down a download list is brute force: most of what you read
does not belong in the map, and the entries that matter are scattered. This
inverts it. Every package the map has no opinion about is scored by how much
that silence costs, and you review the top of the list.

The ranking, most important first:

* **What the advisories say went wrong.** A deserialization flaw, an SQL
  injection, a path traversal while extracting, an authentication bypass:
  each is a statement by whoever wrote the advisory that the package handles
  data an attacker could shape. That is the map's own criterion, so it is
  the strongest evidence available and it leads. The CWE ids come from the
  GitHub-sourced OSV records, and the mapping to categories lives in
  ``package_doctor.cwe``.
* **Unfixed advisories.** If such a package turns out to sit at a trust
  boundary it is dangerous right now and the map is hiding it. But an
  advisory count is a reason to look, never the answer: num2words reached
  the top of an earlier version of this list with three unfixed advisories
  that were a maintainer account compromise. Without a CWE that says
  something about input, an unfixed count now ranks below one that does.
* **Advisories against a pinned version**, then advisories that only prove
  the package parses input (a slow regex, an out-of-bounds read), then an
  archived repository, then any advisory history at all.
* **Downloads** break ties.

Each candidate is printed with what it actually does and what its advisories
cite, because the friction in this job is never the decision - it is looking
up what the package is for.

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
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from package_doctor.cache import Cache
from package_doctor.cwe import boundary_hints
from package_doctor.exposure import load_exposure_map
from package_doctor.sources.client import Client
from package_doctor.sources.osv import OSVSource
from package_doctor.sources.pypi import PyPISource, normalise

CATEGORIES = (
    "auth", "crypto", "deserialization", "parsing", "ml_model", "llm_agent", "markup",
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
    #: category -> CWE ids that argued for it, from the advisories.
    hints: dict[str, list[str]] = field(default_factory=dict)
    #: CWE ids that only show the package parses input.
    weak_hints: list[str] = field(default_factory=list)
    #: The CWE ids were looked up, so an empty result means "none", not "unknown".
    cwes_checked: bool = False

    @property
    def strong(self) -> int:
        return sum(len(v) for v in self.hints.values())

    @property
    def score(self) -> tuple:
        # Ordering only - the numbers below are ranks, not measurements, and
        # nothing downstream treats them as a probability of anything.
        return (
            -self.strong,
            -self.unfixed,
            -self.affecting,
            -len(self.weak_hints),
            -(1 if self.archived else 0),
            -self.advisories,
            -self.downloads,
            self.name,
        )

    @property
    def suggested(self) -> list[str]:
        """Categories the advisories argue for, strongest first."""
        return sorted(self.hints, key=lambda c: (-len(self.hints[c]), c))

    @property
    def why(self) -> str:
        bits = []
        for category in self.suggested:
            bits.append(f"advisories cite {', '.join(self.hints[category])} -> {category}")
        if self.unfixed:
            bits.append(f"{self.unfixed} advisor{'y' if self.unfixed == 1 else 'ies'} never fixed")
        if self.affecting:
            bits.append(f"{self.affecting} affect the pinned version")
        if self.weak_hints:
            bits.append(f"input-handling only: {', '.join(self.weak_hints)}")
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
        candidate = Candidate(
            name=normalise(row["name"]),
            unfixed=row.get("advisories_unfixed") or 0,
            advisories=row.get("advisories_total") or 0,
            downloads=row.get("downloads") or 0,
            archived=bool(row.get("repo_archived")),
            stale_days=row.get("days_since_release"),
            seen_in="dataset",
        )
        # A dataset written by a bulk_scan that records CWE ids saves the
        # lookup; an older one is filled in from OSV below.
        recorded = row.get("advisory_cwes")
        if isinstance(recorded, list):
            candidate.hints, candidate.weak_hints = boundary_hints(
                [{"database_specific": {"cwe_ids": recorded}}]
            )
            candidate.cwes_checked = True
        out.append(candidate)
    return out


async def add_hints(candidates: list[Candidate]) -> None:
    """Read each candidate's advisories for CWE ids. Cached, so a rerun is free."""
    todo = [c for c in candidates if c.advisories and not c.cwes_checked]
    if not todo:
        return
    cache = Cache(ttl=7 * 24 * 3600)
    try:
        async with Client(cache, concurrency=8) as client:
            osv = OSVSource(client)

            async def one(c: Candidate) -> None:
                try:
                    vulns = await osv.fetch(c.name)
                except Exception:
                    return
                c.hints, c.weak_hints = boundary_hints(vulns)
                c.cwes_checked = True

            await asyncio.gather(*(one(c) for c in todo))
    finally:
        cache.close()


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
    p.add_argument("--no-cwe", action="store_true",
                   help="skip the advisory CWE lookup (offline; ranks by maintenance signal)")
    args = p.parse_args()

    source = args.scan or args.dataset
    if not source.exists():
        hint = ("package-doctor scan . --json -o scan.json" if args.scan else
                f"python research/bulk_scan.py --top 3000 --out {source}")
        print(f"No such file: {source}\nCreate one first:  {hint}", file=sys.stderr)
        return 1
    candidates = from_scan(args.scan) if args.scan else from_dataset(args.dataset)

    # Never re-ask about something already decided, in any list or by a family pattern.
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

    if not args.no_cwe:
        asyncio.run(add_hints(candidates))
    candidates.sort(key=lambda c: c.score)
    shortlist = candidates[: args.limit]
    asyncio.run(add_summaries(shortlist))

    if args.emit:
        print("# Paste each stub under the category its advisories suggest, or under")
        print("# [reviewed] not_exposed. Fill in `why` with what convinced you - the")
        print("# advisory, the API, the input it handles. A stub without one fails CI.\n")
        for c in shortlist:
            target = c.suggested[0] if c.suggested else "?"
            evidence = "; ".join(
                f"{', '.join(v)}" for v in c.hints.values()
            )
            print(f"  # {target:<16} {c.summary[:60] or '?'}")
            print(f'  {{ name = "{c.name}", why = "{evidence}" }},')
        return 0

    with_hints = sum(1 for c in candidates if c.hints)
    cite = (
        f", {with_hints} with advisories that cite a trust-boundary weakness"
        if with_hints else ""
    )
    print(f"{len(candidates)} packages have no entry and show some signal{cite}. "
          f"Top {len(shortlist)}:\n")
    for i, c in enumerate(shortlist, 1):
        print(f"{i:>3}. {c.name}")
        print(f"     {c.why}")
        if c.summary:
            print(f"     \"{c.summary[:88]}\"")
        print(f"     https://pypi.org/project/{c.name}/")
        if c.advisories:
            print(f"     https://osv.dev/list?q={c.name}&ecosystem=PyPI")
        print()
    print("For each: does it routinely handle data a stranger sent you?")
    print(f"  yes -> add to one of: {', '.join(CATEGORIES)}")
    print("  no  -> add to [reviewed] not_exposed")
    print("Either way as { name = \"...\", why = \"...\" }, saying what convinced you.")
    print("\nFile: src/package_doctor/data/exposure.toml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
