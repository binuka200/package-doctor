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
from .client import Client, ResponseTooLarge
from .exploitability import CVE_ID
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


def _parse(raw: Any) -> Version | None:
    try:
        return Version(str(raw))
    except InvalidVersion:
        return None


def _affects_version(vuln: dict[str, Any], package: str, version: str) -> bool:
    """Whether a version falls inside an advisory's affected set, as OSV reads it.

    OSV's explicit ``versions`` list is checked first. Ranges are then read
    with OSV's own semantics: an ``introduced`` event opens an interval that a
    ``fixed`` event closes exclusively, a ``last_affected`` event closes
    inclusively, and one that nothing closes runs to infinity.

    The last two matter. GitHub's advisory database encodes most older fixes
    as ``last_affected``, and reading only ``fixed`` made a Django CSRF bug
    from 2011, closed at 1.2.7, look like it had never been fixed. And an
    open-ended range - scrapy's PYSEC-2017-83 is ``introduced: 0.7`` and
    nothing else - affects every version since, which a matcher that waits
    for a ``fixed`` event never reports.
    """
    target = normalise(package)
    current = _parse(version)

    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name") or ""
        if normalise(pkg) != target:
            continue
        listed = affected.get("versions")
        if isinstance(listed, list) and listed:
            if version in listed:
                return True
            # PEP 440 equality, not string equality: tornado publishes "6.3"
            # while a lockfile may pin "6.3.0", and those are the same release.
            if current is not None and any(_parse(c) == current for c in listed):
                return True
            # Fall through to the ranges rather than giving up here. An OSV
            # `versions` list is a convenience, not an exhaustive index, and
            # treating a miss as "not affected" turns a gap into a false
            # negative on a security finding.
        if current is None:
            continue
        for rng in affected.get("ranges") or []:
            introduced: Version | None = None
            open_interval = False
            for event in rng.get("events") or []:
                if "introduced" in event:
                    # A second `introduced` before anything closed the first
                    # means the first ran to infinity.
                    if open_interval and introduced is not None and current >= introduced:
                        return True
                    raw = event["introduced"]
                    introduced = Version("0") if raw == "0" else _parse(raw)
                    open_interval = introduced is not None
                elif "fixed" in event:
                    fixed = _parse(event["fixed"])
                    closed = fixed is not None and open_interval and introduced is not None
                    if closed and introduced <= current < fixed:
                        return True
                    open_interval = False
                elif "last_affected" in event:
                    last = _parse(event["last_affected"])
                    closed = last is not None and open_interval and introduced is not None
                    if closed and introduced <= current <= last:
                        return True
                    open_interval = False
            if open_interval and introduced is not None and current >= introduced:
                return True
    return False


def _is_open_ended(vuln: dict[str, Any], package: str) -> bool:
    """A range with an ``introduced`` that nothing closes.

    Used only when the latest release is unknown, as the fallback definition
    of "no fix": every version since `introduced` is affected, so whatever
    the latest one is, it is too.
    """
    target = normalise(package)
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name") or ""
        if normalise(pkg) != target:
            continue
        for rng in affected.get("ranges") or []:
            pending = False
            for event in rng.get("events") or []:
                if "introduced" in event:
                    if pending:
                        return True
                    pending = True
                elif "fixed" in event or "last_affected" in event:
                    pending = False
            if pending:
                return True
    return False


def _mentions(vuln: dict[str, Any], package: str) -> bool:
    target = normalise(package)
    return any(
        normalise((a.get("package") or {}).get("name") or "") == target
        for a in vuln.get("affected") or []
    )


_ID_PREFERENCE = ("GHSA-", "PYSEC-", "CVE-")


def _canonical_id(ids: list[str]) -> str:
    for prefix in _ID_PREFERENCE:
        for i in ids:
            if i.startswith(prefix):
                return i
    return ids[0]


def _group_by_cve(vulns: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Merge records that describe the same vulnerability.

    OSV routinely carries a GHSA record and a PYSEC record for one CVE, and
    counting both told a user that cryptography 46.0.7 was "affected by 7
    advisories" when it was four distinct issues. Records are grouped by
    shared CVE alias; a record with no CVE stands alone.
    """
    by_cve: dict[str, int] = {}
    groups: list[list[dict[str, Any]]] = []
    for vuln in vulns:
        cves = sorted(str(a) for a in vuln.get("aliases") or [] if CVE_ID.match(str(a)))
        if CVE_ID.match(str(vuln.get("id") or "")):
            cves.append(str(vuln["id"]))
        index = next((by_cve[c] for c in cves if c in by_cve), None)
        if index is None:
            index = len(groups)
            groups.append([])
        groups[index].append(vuln)
        for c in cves:
            by_cve.setdefault(c, index)
    return groups


class OSVSource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch(self, name: str) -> list[dict[str, Any]]:
        """Advisories for a package.

        An over-cap response propagates rather than becoming an empty list:
        "no advisories" is a claim, and one this tool must not make because
        it could not read the answer. The analyzer turns it into an error on
        the finding and a gap, which lands the package in *unknown*.
        """
        try:
            data = await self.client.post_json(
                OSV_QUERY,
                {"package": {"name": name, "ecosystem": "PyPI"}},
                cache_key=f"osv:{normalise(name)}",
            )
        except ResponseTooLarge as exc:
            raise RuntimeError(f"OSV response too large to read: {exc}") from exc
        if not isinstance(data, dict):
            return []
        vulns = data.get("vulns")
        return vulns if isinstance(vulns, list) else []


def build_history(
    package: str,
    vulns: list[dict[str, Any]],
    release_dates: dict[str, dt.datetime],
    current_version: str | None,
    latest_version: str | None = None,
) -> AdvisoryHistory:
    """Read a package's advisories as evidence about its ability to ship fixes.

    "Never fixed" means the latest release is still affected - that is the
    only reading under which "nobody shipped a patch" is a fact rather than an
    inference. An advisory whose affected range ends before the latest
    release, but names no fix version, is counted as *bounded* instead: it is
    closed for anyone on a current version, but there is no fix date to put
    on a timeline. When the latest release is unknown, an open-ended range is
    the fallback definition of unfixed.
    """
    # A record that never names this package says nothing about it. OSV's
    # query is package-scoped so this is rare, but a stray record must not be
    # read as "an advisory nobody fixed".
    groups = _group_by_cve([v for v in vulns if _mentions(v, package)])
    history = AdvisoryHistory(total=len(groups))
    late_windows: list[int] = []
    latest = latest_version if latest_version and _parse(latest_version) else None

    for members in groups:
        vuln_id = _canonical_id([str(v.get("id") or "?") for v in members])
        published_all = [p for v in members if (p := parse_ts(v.get("published")))]
        published = min(published_all) if published_all else None
        fixes = [f for v in members for f in _fixed_versions(v, package)]

        if current_version and any(
            _affects_version(v, package, current_version) for v in members
        ):
            history.affecting_current += 1
            history.ids_affecting_current.append(vuln_id)
            # Keep CVE aliases so exploitability can be scored later. GHSA and
            # PYSEC ids mean nothing to EPSS or KEV, which are CVE-keyed.
            for v in members:
                for alias in v.get("aliases") or []:
                    if CVE_ID.match(str(alias)):
                        history.cves_affecting_current.append(str(alias))

        if latest is not None:
            unfixed = any(_affects_version(v, package, latest) for v in members)
        else:
            unfixed = not fixes and any(_is_open_ended(v, package) for v in members)
        if unfixed:
            history.unfixed += 1
            history.ids_unfixed.append(vuln_id)
            continue

        if not fixes:
            history.bounded += 1
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
    history.cves_affecting_current = sorted(set(history.cves_affecting_current))
    return history
