"""Core data model.

The whole tool turns on two independent axes:

* **Exposure** - does this package sit at a trust boundary, handling data an
  attacker can influence?
* **Remediation capacity** - if a vulnerability landed in it tomorrow, is
  anyone left to ship a fix?

A package is only worth acting on when *both* fire. That rule is what stops
`six` being stale from looking like `legacy-auth` being stale.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """What the user should do about a package, which is the only thing worth sorting on."""

    ACT = "act"          # exposed + no one home
    WATCH = "watch"      # exposed, but actively maintained
    LOW = "low"          # stale, but not at a trust boundary
    UNKNOWN = "unknown"  # not enough signal - deliberately NOT "bad"
    OK = "ok"            # maintained and not exposed


#: Ordering used for report sections and for ``--fail-on``.
VERDICT_ORDER = [Verdict.ACT, Verdict.WATCH, Verdict.LOW, Verdict.UNKNOWN, Verdict.OK]


class Confidence(str, Enum):
    CURATED = "curated"        # human-reviewed entry in the exposure map
    INFERRED = "inferred"      # derived from classifiers/keywords
    NONE = "none"              # no opinion


@dataclass(frozen=True)
class Evidence:
    """A single claim plus somewhere the user can go to check it.

    Every reason shown to a user carries one of these. A finding the user
    cannot verify in one click is a finding they will not trust twice.
    """

    claim: str
    url: str | None = None


@dataclass
class Exposure:
    """Axis 1: does this package handle attacker-controlled input?"""

    categories: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.NONE
    note: str | None = None

    @property
    def is_exposed(self) -> bool:
        return bool(self.categories)

    @property
    def label(self) -> str:
        if not self.categories:
            return "no boundary" if self.confidence is not Confidence.NONE else "unknown"
        return ", ".join(self.categories)


@dataclass
class AdvisoryHistory:
    """What a project's past security advisories say about its ability to ship fixes.

    Derived from OSV advisories joined against PyPI release dates. The useful
    signal is *not* "time to fix" in the naive sense - under coordinated
    disclosure a healthy project publishes the fix at or before the advisory,
    so the honest measure is how often it failed to.
    """

    total: int = 0
    #: Advisories with no fixed version published anywhere - nobody shipped a patch.
    unfixed: int = 0
    #: Advisories whose fix landed only after public disclosure.
    late: int = 0
    #: Advisories whose fix landed at or before disclosure (the healthy case).
    timely: int = 0
    #: Median days of public exposure across the late ones.
    median_late_days: float | None = None
    #: Advisories affecting the *pinned* version specifically.
    affecting_current: int = 0
    ids_unfixed: list[str] = field(default_factory=list)
    ids_affecting_current: list[str] = field(default_factory=list)
    #: CVE aliases of the advisories affecting the pinned version. Only these
    #: are worth scoring: a CVE fixed five releases ago is not your problem.
    cves_affecting_current: list[str] = field(default_factory=list)
    #: Advisories we could not place on a timeline (fix version missing from PyPI).
    unmatched: int = 0
    #: Advisories whose affected range ends before the latest release but
    #: which name no fix version. Closed for anyone current; not datable.
    bounded: int = 0

    @property
    def has_signal(self) -> bool:
        return self.total > 0


@dataclass
class Exploitability:
    """How likely the advisories against your pinned version are to be used.

    Answers the question an advisory count cannot: of these 34, which one first?
    Sourced from CISA KEV (known exploited in the wild) and FIRST EPSS
    (probability of exploitation in the next 30 days).
    """

    #: CVEs on CISA's Known Exploited Vulnerabilities catalogue. Being here is
    #: not a prediction - it means the flaw has been used against real targets.
    kev: list[str] = field(default_factory=list)
    #: (cve, epss probability), highest first.
    scored: list[tuple[str, float]] = field(default_factory=list)
    #: CVEs we tried to score, and how many came back. A CVE with no EPSS entry
    #: is unscored, which is unknown - never "low risk".
    queried: int = 0
    unscored: int = 0
    #: True once a lookup actually ran, so "not checked" stays distinguishable.
    checked: bool = False

    @property
    def top(self) -> tuple[str, float] | None:
        return self.scored[0] if self.scored else None

    def above(self, threshold: float) -> list[tuple[str, float]]:
        return [(c, s) for c, s in self.scored if s >= threshold]


@dataclass
class Remediation:
    """Axis 2: is anyone home to ship a fix?"""

    repo_url: str | None = None
    repo_archived: bool | None = None
    repo_last_push: dt.datetime | None = None
    inactive_classifier: bool = False
    last_release: dt.datetime | None = None
    latest_version: str | None = None
    open_issues: int | None = None
    advisories: AdvisoryHistory = field(default_factory=AdvisoryHistory)
    exploitability: Exploitability = field(default_factory=Exploitability)
    #: Why a signal is missing, so "unknown" can be explained rather than scored.
    gaps: list[str] = field(default_factory=list)

    def days_since_release(self, now: dt.datetime) -> int | None:
        if self.last_release is None:
            return None
        return (now - self.last_release).days

    def days_since_push(self, now: dt.datetime) -> int | None:
        if self.repo_last_push is None:
            return None
        return (now - self.repo_last_push).days


@dataclass
class Package:
    name: str
    version: str | None = None
    direct: bool = True
    #: Which manifest/lockfile this came from, for the "where did this come from" question.
    origins: list[str] = field(default_factory=list)
    #: Places the project's own code imports this package, as "path:line".
    import_sites: list[str] = field(default_factory=list)
    #: True when every import site is in test or tooling code.
    imported_in_tests_only: bool = False
    #: Whether source was scanned at all. Distinguishes "we looked and found no
    #: import" from "we never looked" - and neither means the package is
    #: unreachable, since dependencies call each other at runtime.
    reachability_checked: bool = False

    @property
    def is_imported(self) -> bool:
        return bool(self.import_sites)


@dataclass
class Finding:
    package: Package
    exposure: Exposure
    remediation: Remediation
    verdict: Verdict
    reasons: list[Evidence] = field(default_factory=list)
    #: Signals that argued for "no one home", kept separate so `explain` can show the working.
    abandonment_signals: list[Evidence] = field(default_factory=list)
    error: str | None = None
