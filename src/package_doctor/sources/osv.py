"""OSV advisories, read as evidence of whether a project ships security fixes.

The naive metric - "days from advisory to fix" - is wrong, and the data says so.
Under coordinated disclosure a healthy project publishes the patched release at
or *before* the advisory goes public, so the median delta for well-run projects
is zero or negative. GitHub's advisory backfill makes it worse still: an
advisory written in 2022 for a fix shipped in 2012 produces a ten-year negative.

What the data does support, and what we measure instead:

* **unfixed** - advisories with no fixed version anywhere. Direct evidence that
  nobody shipped a patch. This is the strongest single signal in the tool.
* **late** - advisories whose fix landed only after public disclosure, plus the
  median size of that exposure window.
* **timely** - the healthy case, worth showing so a good project reads as good.
"""

from __future__ import annotations

import datetime as dt
import statistics
from typing import Any

from packaging.version import InvalidVersion, Version

from ..models import AdvisoryHistory
from .client import Client
from .pypi import normalise, parse_ts

OSV_QUERY = "https://api.osv.dev/v1/query"


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    target = normalise(package)
    out: list[str] = []
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name") or ""
        if normalise(pkg) != target:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    out.append(str(event["fixed"]))
    return out


def _affects_version(vuln: dict[str, Any], package: str, version: str) -> bool:
    """Whether a pinned version falls inside an advisory's affected range.

    Prefers OSV's explicit ``versions`` list; falls back to interpreting
    introduced/fixed events as a half-open interval.
    """
    target = normalise(package)
    try:
        current = Version(version)
    except InvalidVersion:
        current = None

    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name") or ""
        if normalise(pkg) != target:
            continue
        listed = affected.get("versions")
        if isinstance(listed, list) and listed:
            if version in listed:
                return True
            continue
        if current is None:
            continue
        for rng in affected.get("ranges") or []:
            introduced: Version | None = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    raw = event["introduced"]
                    if raw == "0":
                        introduced = Version("0")
                        continue
                    try:
                        introduced = Version(raw)
                    except InvalidVersion:
                        introduced = None
                elif "fixed" in event:
                    try:
                        fixed = Version(event["fixed"])
                    except InvalidVersion:
                        continue
                    lower_ok = introduced is None or current >= introduced
                    if lower_ok and current < fixed:
                        return True
    return False


class OSVSource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch(self, name: str) -> list[dict[str, Any]]:
        data = await self.client.post_json(
            OSV_QUERY,
            {"package": {"name": name, "ecosystem": "PyPI"}},
            cache_key=f"osv:{normalise(name)}",
        )
        if not isinstance(data, dict):
            return []
        vulns = data.get("vulns")
        return vulns if isinstance(vulns, list) else []


def build_history(
    package: str,
    vulns: list[dict[str, Any]],
    release_dates: dict[str, dt.datetime],
    current_version: str | None,
) -> AdvisoryHistory:
    history = AdvisoryHistory(total=len(vulns))
    late_windows: list[int] = []

    for vuln in vulns:
        vuln_id = str(vuln.get("id") or "?")
        published = parse_ts(vuln.get("published"))
        fixes = _fixed_versions(vuln, package)

        if current_version and _affects_version(vuln, package, current_version):
            history.affecting_current += 1
            history.ids_affecting_current.append(vuln_id)

        if not fixes:
            history.unfixed += 1
            history.ids_unfixed.append(vuln_id)
            continue

        # The first fix to reach users is what closed the window.
        fix_dates = [release_dates[v] for v in fixes if v in release_dates]
        if not fix_dates or published is None:
            history.unmatched += 1
            continue

        delta_days = (min(fix_dates) - published).days
        if delta_days > 0:
            history.late += 1
            late_windows.append(delta_days)
        else:
            history.timely += 1

    if late_windows:
        history.median_late_days = float(statistics.median(late_windows))
    return history
