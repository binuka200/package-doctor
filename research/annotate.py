#!/usr/bin/env python3
"""A second reader for the exposure map, and a number for how much they agree.

The map is one person's judgement about which packages sit where an attacker
can reach. That is its stated weakness: a single annotator has no way to
know which of their calls another careful reader would reject. This script
is the instrument for finding out. It draws a blind sample, walks a second
reader through it with the same evidence the curator had, and reports
Cohen's kappa between the two - the standard statistic for inter-annotator
agreement, corrected for the agreement two people would reach by chance.

Three steps:

    python research/annotate.py sample --out research/annotations/sample.json
    python research/annotate.py run research/annotations/sample.json --annotator alice
    python research/annotate.py agree research/annotations/sample.json \
        research/annotations/alice.jsonl

**sample** draws packages from four strata - the map's categories in
proportion to their size, the reviewed-and-cleared list, the stable list,
and packages the map has no opinion about (from a bulk-scan dataset when
one is given) - shuffles them, and fetches what each one is for: the PyPI
summary, its topic classifiers, and its advisories with their CWE ids. The
curator's answer is deliberately *not* written to the sample: the reader
must not be able to see it, and `agree` recomputes it from the map.

**run** is the reading session. One package at a time, the evidence, and a
prompt for a category, `n` for not exposed, or `s` to skip. A note can be
added to any decision and is the most valuable part of the record - it is
what becomes the `why` of a map entry. Decisions append to a JSONL file,
so a session can be interrupted and resumed.

**agree** reports two kappas. The binary one - exposed or not - is the
number that matters, because that is the distinction the verdict turns
on. The category-level one is stricter and mostly tells you where the
category boundaries are unclear. Every disagreement is listed with both
sides' reasoning, because the disagreements are the point: each is either
a wrong entry to fix or a criterion to write down. Decisions about
packages the map had no opinion on cannot be scored, so they are printed
as ready-to-paste entries instead.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import random
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from package_doctor.cache import Cache
from package_doctor.cwe import cwe_ids
from package_doctor.exposure import DATA_FILE, entries
from package_doctor.sources.client import Client
from package_doctor.sources.osv import OSVSource, _group_by_cve
from package_doctor.sources.pypi import PyPISource, normalise

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

NOT_EXPOSED = "not_exposed"
SKIP = "skip"

#: Share of the sample drawn from each stratum. Categories carry the most
#: weight because that is where a wrong call does the most harm; the
#: unreviewed stratum is where a second reader finds what the map missed.
STRATA = {"category": 0.50, "reviewed": 0.20, "stable": 0.05, "unreviewed": 0.25}


# --- the curator's answer, from the map ------------------------------------

def load_raw_map(path: Path = DATA_FILE) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def curator_decisions(raw: dict[str, Any]) -> dict[str, set[str]]:
    """normalised name -> the set of category keys, or {NOT_EXPOSED}.

    Packages in neither list are absent: the map has no opinion about them,
    and no agreement can be measured.
    """
    out: dict[str, set[str]] = {}
    for key, block in (raw.get("category") or {}).items():
        for name, _ in entries(block.get("packages")):
            out.setdefault(normalise(name), set()).add(key)
    for name, _ in entries((raw.get("reviewed") or {}).get("not_exposed")):
        out.setdefault(normalise(name), {NOT_EXPOSED})
    for name, _ in entries((raw.get("stable") or {}).get("packages")):
        out.setdefault(normalise(name), {NOT_EXPOSED})
    return out


def category_keys(raw: dict[str, Any]) -> list[str]:
    return list((raw.get("category") or {}).keys())


# --- sampling ---------------------------------------------------------------

def stratified_sample(
    raw: dict[str, Any],
    unreviewed_pool: Iterable[str],
    size: int,
    seed: int,
) -> list[str]:
    """Draw ``size`` names across the strata, in a shuffled order.

    Within the category stratum, each category contributes in proportion to
    its size, and every category contributes at least one so the small ones
    (templating has six entries) are not skipped by rounding. The result
    carries no stratum labels: the reader is blind to where a name came
    from, which is what makes the agreement number mean anything.
    """
    rng = random.Random(seed)
    decisions = curator_decisions(raw)
    by_category: dict[str, list[str]] = {}
    for name, keys in decisions.items():
        for key in keys:
            if key != NOT_EXPOSED:
                by_category.setdefault(key, []).append(name)
    reviewed = sorted(
        normalise(n) for n, _ in entries((raw.get("reviewed") or {}).get("not_exposed"))
    )
    stable = sorted(normalise(n) for n, _ in entries((raw.get("stable") or {}).get("packages")))
    pool = sorted({normalise(n) for n in unreviewed_pool} - set(decisions))

    want = {k: round(size * share) for k, share in STRATA.items()}
    if not pool:
        # No dataset: give the unreviewed share back to the categories.
        want["category"] += want.pop("unreviewed")
        want["unreviewed"] = 0

    chosen: list[str] = []
    picked: set[str] = set()

    def take(candidates: list[str], n: int) -> None:
        fresh = [c for c in sorted(candidates) if c not in picked]
        rng.shuffle(fresh)
        for name in fresh[: max(n, 0)]:
            chosen.append(name)
            picked.add(name)

    total_curated = sum(len(v) for v in by_category.values()) or 1
    quota = {k: max(1, round(want["category"] * len(v) / total_curated))
             for k, v in by_category.items()}
    for key in sorted(by_category):
        take(by_category[key], quota[key])
    take(reviewed, want["reviewed"])
    take(stable, want["stable"])
    take(pool, want["unreviewed"])
    rng.shuffle(chosen)
    return chosen[:size] if len(chosen) > size else chosen


def read_dataset(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" not in row and row.get("name"):
            names.append(str(row["name"]))
    return names


async def fetch_context(names: list[str]) -> dict[str, dict[str, Any]]:
    """What the reader needs to decide: summary, topics, advisories."""
    out: dict[str, dict[str, Any]] = {}
    cache = Cache(ttl=7 * 24 * 3600)
    try:
        async with Client(cache, concurrency=8) as client:
            pypi, osv = PyPISource(client), OSVSource(client)

            async def one(name: str) -> None:
                data, vulns = await asyncio.gather(pypi.fetch(name), osv.fetch(name))
                info = (data or {}).get("info") or {}
                advisories = []
                for group in _group_by_cve(vulns)[:8]:
                    advisories.append({
                        "id": str(group[0].get("id") or "?"),
                        "summary": next(
                            (str(v.get("summary")) for v in group if v.get("summary")), ""
                        )[:160],
                        "cwes": sorted({c for v in group for c in cwe_ids(v)}),
                    })
                out[name] = {
                    "name": name,
                    "summary": (info.get("summary") or "").strip()[:200],
                    "topics": [
                        c for c in info.get("classifiers") or []
                        if str(c).startswith("Topic ::")
                    ][:6],
                    "advisories": advisories,
                    "advisory_count": len(_group_by_cve(vulns)),
                    "url": f"https://pypi.org/project/{name}/",
                }

            await asyncio.gather(*(one(n) for n in names))
    finally:
        cache.close()
    return out


# --- the reading session ----------------------------------------------------

def _show(item: dict[str, Any], index: int, total: int, keys: list[str]) -> None:
    print(f"\n[{index}/{total}] {item['name']}")
    print(f"  {item.get('summary') or '(no summary on PyPI)'}")
    for topic in item.get("topics") or []:
        print(f"  {topic}")
    advisories = item.get("advisories") or []
    if advisories:
        print(f"  advisories ({item.get('advisory_count', len(advisories))}):")
        for adv in advisories:
            cwes = f" [{', '.join(adv['cwes'])}]" if adv.get("cwes") else ""
            print(f"    {adv['id']}{cwes} {adv.get('summary', '')}")
    else:
        print("  advisories: none on record")
    print(f"  {item.get('url', '')}")
    print(f"  categories: {' '.join(keys)}")


def run_session(sample: list[dict[str, Any]], keys: list[str], annotator: str, out: Path) -> int:
    done: set[str] = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["name"])
            except (json.JSONDecodeError, KeyError):
                continue
    todo = [item for item in sample if item["name"] not in done]
    if not todo:
        print("Every package in the sample is annotated.")
        return 0
    print("Does this package routinely handle data a stranger sent you?")
    print("Answer with a category key, `n` for not exposed, `s` to skip, `q` to stop.")
    print("Add a note after a space: `deserialization pickles the job store`.")
    with out.open("a", encoding="utf-8") as fh:
        for i, item in enumerate(todo, start=len(done) + 1):
            _show(item, i, len(sample), keys)
            while True:
                try:
                    raw = input("> ").strip()
                except EOFError:
                    raw = "q"
                if raw == "q":
                    print(f"Stopped. {i - 1} of {len(sample)} annotated; rerun to resume.")
                    return 0
                decision, _, note = raw.partition(" ")
                if decision == "s":
                    decision = SKIP
                elif decision == "n":
                    decision = NOT_EXPOSED
                elif decision not in keys:
                    print(f"  one of: {' '.join(keys)}, n, s, q")
                    continue
                fh.write(json.dumps({
                    "name": item["name"],
                    "decision": decision,
                    "note": note.strip(),
                    "annotator": annotator,
                    "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                }) + "\n")
                fh.flush()
                break
    print(f"\nDone: {len(sample)} annotated in {out}.")
    return 0


# --- agreement --------------------------------------------------------------

def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's kappa for two raters over the same items.

    Observed agreement minus the agreement expected from each rater's
    marginal label frequencies, scaled so that 1 is perfect and 0 is chance.
    Undefined on an empty list; 1.0 when both raters used a single label
    identically, where the textbook formula divides by zero.
    """
    if not pairs:
        return None
    n = len(pairs)
    observed = sum(1 for a, b in pairs if a == b) / n
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    expected = sum(left[label] * right[label] for label in set(left) | set(right)) / (n * n)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def describe_kappa(value: float | None) -> str:
    if value is None:
        return "undefined (nothing to compare)"
    # Landis and Koch's bands, the usual reading of the statistic.
    for ceiling, word in ((0.0, "poor"), (0.2, "slight"), (0.4, "fair"),
                          (0.6, "moderate"), (0.8, "substantial")):
        if value <= ceiling:
            return f"{value:.2f} ({word})"
    return f"{value:.2f} (almost perfect)"


def agreement(
    annotations: list[dict[str, Any]],
    curator: dict[str, set[str]],
) -> dict[str, Any]:
    """Score one reader's decisions against the map.

    Binary pairs compare exposed-or-not. Category pairs compare the reader's
    category with the curator's; where the curator recorded more than one
    category, the reader is credited with a match if theirs is among them.
    """
    binary: list[tuple[str, str]] = []
    categorical: list[tuple[str, str]] = []
    disagreements: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    skipped = 0
    for row in annotations:
        decision = row.get("decision")
        if decision in (None, SKIP):
            skipped += 1
            continue
        name = normalise(str(row.get("name") or ""))
        theirs = curator.get(name)
        if theirs is None:
            proposals.append(row)
            continue
        curated_exposed = NOT_EXPOSED not in theirs
        reader_exposed = decision != NOT_EXPOSED
        binary.append(("exposed" if curated_exposed else NOT_EXPOSED,
                       "exposed" if reader_exposed else NOT_EXPOSED))
        curated_label = decision if decision in theirs else sorted(theirs)[0]
        categorical.append((curated_label, decision))
        if curated_exposed != reader_exposed or decision not in theirs:
            disagreements.append({
                "name": name,
                "curator": sorted(theirs),
                "reader": decision,
                "note": row.get("note") or "",
                "kind": "boundary" if curated_exposed != reader_exposed else "category",
            })
    confusion = Counter(binary)
    return {
        "compared": len(binary),
        "skipped": skipped,
        "proposals": proposals,
        "binary_kappa": cohen_kappa(binary),
        "binary_agreement": (sum(1 for a, b in binary if a == b) / len(binary)) if binary else None,
        "category_kappa": cohen_kappa(categorical),
        "confusion": {
            "both_exposed": confusion[("exposed", "exposed")],
            "both_not": confusion[(NOT_EXPOSED, NOT_EXPOSED)],
            "curator_only": confusion[("exposed", NOT_EXPOSED)],
            "reader_only": confusion[(NOT_EXPOSED, "exposed")],
        },
        "disagreements": disagreements,
    }


def print_agreement(report: dict[str, Any], annotator: str) -> None:
    c = report["confusion"]
    skipped = f", {report['skipped']} skipped" if report["skipped"] else ""
    print(f"Agreement between the map and {annotator}")
    print(f"  compared {report['compared']} packages the map has an opinion on{skipped}")
    if report["binary_agreement"] is not None:
        print(f"  exposed or not:  agreement {report['binary_agreement']:.0%}, "
              f"kappa {describe_kappa(report['binary_kappa'])}")
        print(f"  by category:     kappa {describe_kappa(report['category_kappa'])}")
        print("\n                    reader: exposed   reader: not")
        print(f"  map: exposed      {c['both_exposed']:>8}   {c['curator_only']:>11}")
        print(f"  map: not          {c['reader_only']:>8}   {c['both_not']:>11}")
    boundary = [d for d in report["disagreements"] if d["kind"] == "boundary"]
    category = [d for d in report["disagreements"] if d["kind"] == "category"]
    if boundary:
        print(f"\nDisagree on whether it is exposed ({len(boundary)}) - each is a wrong "
              "entry or a missing criterion:")
        for d in boundary:
            print(f"  {d['name']}: map says {', '.join(d['curator'])}, "
                  f"{annotator} says {d['reader']}"
                  + (f" - {d['note']}" if d["note"] else ""))
    if category:
        print(f"\nAgree it is exposed, differ on category ({len(category)}):")
        for d in category:
            print(f"  {d['name']}: map {', '.join(d['curator'])}, {annotator} {d['reader']}"
                  + (f" - {d['note']}" if d["note"] else ""))
    if report["proposals"]:
        print(f"\nPackages the map had no opinion on ({len(report['proposals'])}) - "
              f"{annotator}'s calls, as entries to paste:")
        for row in report["proposals"]:
            target = row["decision"] if row["decision"] != NOT_EXPOSED else "[reviewed] not_exposed"
            note = (row.get("note") or "").replace('"', "'")
            print(f'  # {target}')
            print(f'  {{ name = "{normalise(row["name"])}", why = "{note}" }},')


# --- entry point ------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sample", help="draw a blind sample and fetch its evidence")
    s.add_argument("--out", type=Path, required=True, help="where to write the sample JSON")
    s.add_argument("--dataset", type=Path, help="JSONL from research/bulk_scan.py, for the "
                                                "unreviewed stratum")
    s.add_argument("--size", type=int, default=100)
    s.add_argument("--seed", type=int, default=1)

    r = sub.add_parser("run", help="annotate a sample interactively")
    r.add_argument("sample", type=Path)
    r.add_argument("--annotator", required=True, help="your name, recorded on each decision")
    r.add_argument("--out", type=Path, help="JSONL to append to (default: next to the sample)")

    a = sub.add_parser("agree", help="score annotations against the map")
    a.add_argument("sample", type=Path)
    a.add_argument("annotations", type=Path)
    a.add_argument("--json", action="store_true", help="print the report as JSON")

    args = p.parse_args()
    raw = load_raw_map()

    if args.command == "sample":
        names = stratified_sample(raw, read_dataset(args.dataset), args.size, args.seed)
        if not args.dataset:
            print("No --dataset: the sample has no unreviewed stratum, so it can "
                  "measure agreement but not find what the map missed.", file=sys.stderr)
        context = asyncio.run(fetch_context(names))
        sample = [context.get(n, {"name": n}) for n in names]
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({
            "seed": args.seed,
            "size": len(sample),
            "categories": category_keys(raw),
            "drawn": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "items": sample,
        }, indent=1), encoding="utf-8")
        print(f"Wrote {len(sample)} packages to {args.out}. The curator's answers are "
              "not in the file.")
        return 0

    sample_doc = json.loads(args.sample.read_text(encoding="utf-8"))
    if args.command == "run":
        out = args.out or args.sample.with_name(f"{args.annotator}.jsonl")
        return run_session(sample_doc["items"], sample_doc["categories"], args.annotator, out)

    annotations = [
        json.loads(line)
        for line in args.annotations.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    report = agreement(annotations, curator_decisions(raw))
    if args.json:
        print(json.dumps(report, indent=1))
        return 0
    annotator = next((str(r.get("annotator")) for r in annotations if r.get("annotator")),
                     args.annotations.stem)
    print_agreement(report, annotator)
    return 0


if __name__ == "__main__":
    sys.exit(main())
