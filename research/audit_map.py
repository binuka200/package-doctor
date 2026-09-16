#!/usr/bin/env python3
"""Where the exposure map's answers disagree with the advisories.

suggest_map.py reads advisories to find packages the map has no opinion
about. This reads them in the other direction, against the answers the map
already gives, because a wrong entry is worse than a missing one: a missing
entry surfaces as "boundary not reviewed", while a wrong one looks exactly
like a reviewed answer.

Three disagreements are reported:

* **cleared with evidence** - a package recorded as not at a boundary whose
  own advisories cite a trust-boundary weakness (CWE-502, CWE-78, CWE-79...).
  Often the call is still right: black's path-traversal advisory is about its
  cache file, not about input. But then the entry has to say so.
* **understated consequence** - a package at a boundary whose advisories
  point to a category with a worse consequence than any it is recorded
  under. langchain-core is llm/agent, "prompt injection", while its
  advisories are deserialization and code injection. The report sorts by
  consequence, so this misorders findings in every scan that has one.
* **unknown citation** - a `why` names an advisory id OSV has never heard
  of: a typo, or a CVE that was rejected in favour of another. An id that
  belongs to a different package is fine - pyarrow-hotfix is the fix for
  pyarrow's CVE, and pygit2 cites libgit2's.

The rule that resolves the first two is the same, and it is the map's own
rule: an advisory that would change the call is named in a `why`. Either the
entry that acts on it cites it (`{ name = "langchain-core", why = "GHSA-...:
serialization injection..." }` under deserialization), or the entry that
declines to cites it and says why it does not count. Silence is the only
thing reported.

Path-traversal and link-following CWEs are left out of the consequence check
by default. The CWE table maps them to archive extraction, but in a web
server or a CLI they are a file read, and counting them flags almost every
framework in the map. `--include-paths` puts them back.

Only GitHub-sourced OSV records carry CWE ids, so this is a floor, not a
census: an advisory without one cannot disagree with anything.

    python research/audit_map.py
    python research/audit_map.py --package langchain-core --package ipython
    python research/audit_map.py --scan out/*.json      # family members seen in real scans too
    python research/audit_map.py --json -o audit.json
    python research/audit_map.py --strict               # exit 1 on any disagreement, for CI

Advisories are cached, so a rerun after editing the map is free. A package
whose advisories cannot be read is listed but does not fail --strict: an OSV
outage is not a defect in the map, the same line the live contract tests draw.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from package_doctor.cache import Cache
from package_doctor.cwe import STRONG, cwe_ids
from package_doctor.exposure import (
    DATA_FILE,
    consequence_rank,
    entries,
    load_exposure_map,
)
from package_doctor.sources.client import Client
from package_doctor.sources.osv import OSVSource
from package_doctor.sources.pypi import normalise

#: Weaknesses in how a path is built. Real, but they say "touches the
#: filesystem", not "extracts archives", so they do not argue for a worse
#: consequence unless asked to.
PATH_CWES = frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-61"})

OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"

ADVISORY_ID = re.compile(r"\b(?:GHSA(?:-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)\b", re.I)


@dataclass
class Evidence:
    """One advisory that argues for a category, and every id it goes by."""
    ids: list[str]
    category: str
    cwes: list[str]
    summary: str


@dataclass
class Finding:
    package: str
    kind: str
    recorded: str
    #: What the advisories argue for instead.
    suggests: str
    evidence: list[Evidence] = field(default_factory=list)
    why: str | None = None

    def line(self) -> str:
        return f"{self.package}: {self.recorded} -> {self.suggests}"


def advisory_ids(vuln: dict[str, Any]) -> set[str]:
    return {i.upper() for i in [vuln.get("id", ""), *(vuln.get("aliases") or [])] if i}


def first_line(text: str | None) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0][:120] if lines else ""


def cited(why: str | None) -> set[str]:
    return {m.upper() for m in ADVISORY_ID.findall(why or "")}


def evidence_for(vulns: list[dict[str, Any]]) -> list[Evidence]:
    """Every advisory that cites a strong CWE, one row per category it argues for."""
    out = []
    for vuln in vulns:
        if vuln.get("withdrawn"):
            continue
        by_category: dict[str, list[str]] = {}
        for cwe in cwe_ids(vuln):
            category = STRONG.get(cwe)
            if category:
                by_category.setdefault(category, []).append(cwe)
        for category, cwes in by_category.items():
            out.append(Evidence(
                ids=sorted(advisory_ids(vuln)),
                category=category,
                cwes=cwes,
                summary=first_line(vuln.get("summary") or vuln.get("details")),
            ))
    return out


class MapView:
    """The raw map, read once, in the shapes the checks need."""

    def __init__(self, path: Path = DATA_FILE):
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
        self.map = load_exposure_map(str(path))
        #: category key -> (label, consequence)
        self.categories = {
            key: (block.get("label", key), block.get("consequence"))
            for key, block in raw["category"].items()
        }
        self.label_to_key = {label: key for key, (label, _) in self.categories.items()}
        #: normalised name -> every `why` recorded for it anywhere, joined.
        self.whys: dict[str, str] = {}
        self.exposed: dict[str, set[str]] = {}
        self.cleared: set[str] = set()

        def note(name: str, why: str | None) -> None:
            if why:
                key = normalise(name)
                self.whys[key] = f"{self.whys[key]} / {why}" if key in self.whys else why

        for key, block in raw["category"].items():
            for name, why in entries(block.get("packages")):
                self.exposed.setdefault(normalise(name), set()).add(key)
                note(name, why)
        stable = raw.get("stable") or {}
        for name, why in entries(stable.get("packages")):
            self.cleared.add(normalise(name))
            note(name, why)
        for name, why in entries(stable.get("mature")):
            note(name, why)
        for name, why in entries((raw.get("reviewed") or {}).get("not_exposed")):
            self.cleared.add(normalise(name))
            note(name, why)

    def named(self) -> set[str]:
        return set(self.exposed) | self.cleared

    def consequence_of(self, keys: set[str]) -> str | None:
        found = [self.categories[k][1] for k in keys if self.categories[k][1]]
        return min(found, key=consequence_rank) if found else None


def audit_one(
    view: MapView, name: str, vulns: list[dict[str, Any]], include_paths: bool
) -> list[Finding]:
    key = normalise(name)
    findings: list[Finding] = []
    known = set().union(*(advisory_ids(v) for v in vulns)) if vulns else set()
    why = view.whys.get(key)
    family = None if key in view.whys or key in view.named() else view.map.family_for(key)
    if family:
        why = family[1]
    citations = cited(why)

    unknown = sorted(c for c in citations if c not in known)
    if unknown and not family:
        # Candidates only: main() drops the ids OSV knows under another package.
        findings.append(Finding(key, "unknown citation", ", ".join(unknown),
                                "not found in OSV", why=why))

    evidence = evidence_for(vulns)
    uncited = [e for e in evidence if not citations & set(e.ids)]
    if not uncited:
        return findings

    if key in view.cleared or family:
        where = f"reviewed family {family[0]}" if family else "not exposed"
        suggests = sorted({e.category for e in uncited})
        findings.append(Finding(key, "cleared with evidence", where,
                                ", ".join(suggests), uncited, why))
        return findings

    if key in view.exposed:
        recorded = view.exposed[key]
        now = view.consequence_of(recorded)
        worse = [
            e for e in uncited
            if e.category not in recorded
            and e.category in view.categories
            and (include_paths or not set(e.cwes) <= PATH_CWES)
            and consequence_rank(view.categories[e.category][1]) < consequence_rank(now)
        ]
        if worse:
            best = min((view.categories[e.category][1] for e in worse), key=consequence_rank)
            labels = ", ".join(sorted(view.categories[k][0] for k in recorded))
            findings.append(Finding(
                key, "understated consequence", f"{labels} ({now})",
                f"{', '.join(sorted({e.category for e in worse}))} ({best})", worse, why,
            ))
    return findings


async def fetch_all(names: list[str]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    cache = Cache(ttl=7 * 24 * 3600)
    got: dict[str, list[dict[str, Any]]] = {}
    failed: dict[str, str] = {}
    try:
        async with Client(cache, concurrency=8) as client:
            osv = OSVSource(client)

            async def one(name: str) -> None:
                try:
                    got[name] = await osv.fetch(name)
                except Exception as exc:  # reported, never mistaken for "clean"
                    failed[name] = str(exc)[:120]

            await asyncio.gather(*(one(n) for n in names))
    finally:
        cache.close()
    return got, failed


async def missing_from_osv(ids: set[str]) -> set[str]:
    """The ids OSV answers 404 for. A lookup that fails otherwise is not "missing"."""
    cache = Cache(ttl=7 * 24 * 3600)
    missing: set[str] = set()
    try:
        async with Client(cache, concurrency=8) as client:

            async def one(ident: str) -> None:
                try:
                    body = await client.get_json(OSV_VULN.format(id=ident),
                                                 cache_key=f"osv:vuln:{ident}")
                except Exception:
                    return
                if body is None:
                    missing.add(ident)

            await asyncio.gather(*(one(i) for i in sorted(ids)))
    finally:
        cache.close()
    return missing


def names_from_scans(paths: list[Path]) -> set[str]:
    out = set()
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        out.update(normalise(f["name"]) for f in data.get("findings", []))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--package", action="append", default=[],
                   help="audit only this package (repeatable)")
    p.add_argument("--scan", type=Path, nargs="+", default=[],
                   help="scan JSON files; family-matched packages in them are audited too")
    p.add_argument("--include-paths", action="store_true",
                   help="let path-traversal CWEs argue for a worse consequence")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--output", "-o", type=Path, help="write JSON here")
    p.add_argument("--strict", action="store_true", help="exit 1 when a disagreement is found")
    args = p.parse_args()

    view = MapView()
    if args.package:
        names = sorted({normalise(n) for n in args.package})
    else:
        names = set(view.named())
        if args.scan:
            names |= {n for n in names_from_scans(args.scan) if view.map.family_for(n)}
        names = sorted(names)

    vulns, failed = asyncio.run(fetch_all(names))
    findings = [f for n in names if n in vulns
                for f in audit_one(view, n, vulns[n], args.include_paths)]
    candidates = {
        i for f in findings if f.kind == "unknown citation" for i in f.recorded.split(", ")
    }
    if candidates:
        missing = asyncio.run(missing_from_osv(candidates))
        kept = []
        for f in findings:
            if f.kind == "unknown citation":
                ids = [i for i in f.recorded.split(", ") if i in missing]
                if not ids:
                    continue
                f.recorded = ", ".join(ids)
            kept.append(f)
        findings = kept

    if args.json or args.output:
        body = json.dumps({
            "audited": len(names),
            "unreadable": failed,
            "findings": [asdict(f) for f in findings],
        }, indent=1)
        if args.output:
            args.output.write_text(body + "\n", encoding="utf-8")
        else:
            print(body)
    if not args.json:
        order = ("cleared with evidence", "understated consequence", "unknown citation")
        print(f"Audited {len(names)} packages against their advisories; "
              f"{len(findings)} disagreement{'s' if len(findings) != 1 else ''}.")
        if failed:
            print(f"Could not read advisories for {len(failed)}: {', '.join(sorted(failed))}")
        for kind in order:
            group = [f for f in findings if f.kind == kind]
            if not group:
                continue
            print(f"\n{kind.upper()} ({len(group)})")
            for f in group:
                print(f"  {f.line()}")
                if f.why:
                    print(f"      why: {f.why[:140]}")
                for e in f.evidence[:4]:
                    ident = next((i for i in e.ids if i.startswith("GHSA")), e.ids[0])
                    print(f"      {ident}  {'/'.join(e.cwes)} -> {e.category}  {e.summary[:70]}")
                if len(f.evidence) > 4:
                    print(f"      (+{len(f.evidence) - 4} more)")
        if findings:
            print("\nResolve each by naming the advisory in a `why`: on a new entry that acts "
                  "on it, or on the existing one, saying why it does not change the call.")
    return 1 if (args.strict and findings) else 0


if __name__ == "__main__":
    sys.exit(main())
