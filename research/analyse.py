#!/usr/bin/env python3
"""Summarise a bulk_scan dataset.

The central measure is the **remediation gap**: of the advisories published
against a package, how many never received a fix. That is the measurable form
of "discovery is automated, remediation still needs a human".

Two rules this script follows, because the whole point is a number that
survives scrutiny:

* Every figure is printed with its denominator. A rate without an n is a
  rhetorical device, not a finding.
* Cuts below --min-n are shown as counts only. A 100% rate over three packages
  is noise, and presenting it as a percentage invites a false conclusion.

Usage:
    python research/analyse.py data/pypi.jsonl
    python research/analyse.py data/pypi.jsonl --min-n 30 --csv out.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

#: Categories that make up the AI/ML surface, per the scanner's exposure map.
AI_CATEGORIES = {"llm/agent", "model loading"}


def load(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" not in row:
            rows.append(row)
    return rows


def pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:>5.1f}%" if whole else "    - "


class Group:
    """One slice of the dataset, with the figures that matter for it."""

    def __init__(self, name: str):
        self.name = name
        self.packages = 0
        self.with_history = 0        # packages that have ever had an advisory
        self.with_unfixed = 0        # ...of which some advisory was never fixed
        self.advisories = 0
        self.unfixed = 0
        self.timely = 0
        self.late = 0
        self.archived = 0
        self.repo_known = 0
        self.stale_2y = 0
        self.dated = 0
        self.late_windows: list[float] = []

    def add(self, row: dict) -> None:
        self.packages += 1
        total = row.get("advisories_total") or 0
        unfixed = row.get("advisories_unfixed") or 0
        if total:
            self.with_history += 1
            self.advisories += total
            self.unfixed += unfixed
            self.timely += row.get("advisories_timely") or 0
            self.late += row.get("advisories_late") or 0
            if unfixed:
                self.with_unfixed += 1
            if row.get("median_late_days") is not None:
                self.late_windows.append(float(row["median_late_days"]))
        if row.get("repo_archived") is not None:
            self.repo_known += 1
            if row["repo_archived"]:
                self.archived += 1
        days = row.get("days_since_release")
        if days is not None:
            self.dated += 1
            if days > 730:
                self.stale_2y += 1

    @property
    def median_late(self) -> float | None:
        return statistics.median(self.late_windows) if self.late_windows else None

    def as_dict(self) -> dict:
        return {
            "group": self.name,
            "packages": self.packages,
            "with_advisory_history": self.with_history,
            "carrying_unfixed": self.with_unfixed,
            "pct_carrying_unfixed": round(100 * self.with_unfixed / self.with_history, 2)
            if self.with_history else None,
            "advisories": self.advisories,
            "never_fixed": self.unfixed,
            "pct_never_fixed": round(100 * self.unfixed / self.advisories, 2)
            if self.advisories else None,
            "archived_repos": self.archived,
            "repos_checked": self.repo_known,
            "stale_over_2y": self.stale_2y,
            "packages_dated": self.dated,
            "median_late_fix_days": self.median_late,
        }


def report(groups: list[Group], min_n: int, title: str) -> None:
    print(f"\n{title}")
    print(f"{'group':<26}{'pkgs':>6}{'w/hist':>8}{'unfixed pkgs':>14}"
          f"{'advisories':>12}{'never fixed':>14}")
    print("-" * 80)
    for g in groups:
        if not g.packages:
            continue
        small = g.with_history < min_n
        unfixed_cell = (
            f"{g.with_unfixed:>6}      " if small
            else f"{g.with_unfixed:>6} {pct(g.with_unfixed, g.with_history)}"
        )
        never_cell = (
            f"{g.unfixed:>6}      " if small
            else f"{g.unfixed:>6} {pct(g.unfixed, g.advisories)}"
        )
        flag = "  *" if small else ""
        print(f"{g.name:<26}{g.packages:>6}{g.with_history:>8}{unfixed_cell:>14}"
              f"{g.advisories:>12}{never_cell:>14}{flag}")
    if any(g.with_history < min_n and g.packages for g in groups):
        print(f"\n  * fewer than {min_n} packages with advisory history: counts only,"
              f"\n    because a rate over a handful of packages is not a rate.")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("dataset", type=Path)
    p.add_argument("--min-n", type=int, default=20,
                   help="below this many packages with history, show counts only")
    p.add_argument("--csv", type=Path, help="also write the group table as CSV")
    args = p.parse_args()

    if not args.dataset.exists():
        print(f"No dataset at {args.dataset}.\n"
              f"Build one first:  python research/bulk_scan.py --top 3000 "
              f"--out {args.dataset}", file=sys.stderr)
        return 1
    rows = load(args.dataset)
    if not rows:
        print("no usable rows", file=sys.stderr)
        return 1

    overall = Group("ALL")
    ai, rest = Group("AI / ML"), Group("everything else")
    by_cat: dict[str, Group] = defaultdict(lambda: Group(""))
    unreviewed = Group("(not in exposure map)")

    for row in rows:
        overall.add(row)
        cats = row.get("exposure") or []
        curated = row.get("exposure_confidence") == "curated"
        if curated and cats:
            for c in cats:
                g = by_cat[c]
                g.name = g.name or c
                g.add(row)
            (ai if AI_CATEGORIES & set(cats) else rest).add(row)
        elif not row.get("reviewed"):
            unreviewed.add(row)

    print(f"dataset: {args.dataset}  ({len(rows)} packages with usable metadata)")
    print(f"collected: {rows[0].get('collected', '?')}")

    print("\noverall")
    print(f"  packages with any advisory history : {overall.with_history} "
          f"of {overall.packages}")
    print(f"  advisories published               : {overall.advisories}")
    print(f"  never fixed                        : {overall.unfixed}  "
          f"({pct(overall.unfixed, overall.advisories).strip()})")
    print(f"  fixed at or before disclosure      : {overall.timely}  "
          f"({pct(overall.timely, overall.advisories).strip()})")
    print(f"  fixed only after disclosure        : {overall.late}  "
          f"({pct(overall.late, overall.advisories).strip()})")
    if overall.median_late is not None:
        print(f"  median exposure when late          : {overall.median_late:.0f} days")
    print(f"  repositories archived              : {overall.archived} "
          f"of {overall.repo_known} checked")
    print(f"  no release in over 2 years         : {overall.stale_2y} "
          f"of {overall.dated} dated")

    report([ai, rest], args.min_n,
           "the question: does the AI/ML surface remediate worse?")
    report(sorted(by_cat.values(), key=lambda g: -g.with_history) + [unreviewed],
           args.min_n, "by trust-boundary category")

    if args.csv:
        groups = [overall, ai, rest, *by_cat.values(), unreviewed]
        with args.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(overall.as_dict()))
            w.writeheader()
            for g in groups:
                if g.packages:
                    w.writerow(g.as_dict())
        print(f"\nwrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
