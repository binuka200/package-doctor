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
    """What the user should do about a package, which is the only thing worth sorting on.

    Each is named for the action it asks for rather than the reasoning behind
    it, so a section header is an instruction and not a diagnosis to decode.
    """

    EXPLOITED = "exploited"  # known exploited, and the pinned version is affected
    REPLACE = "replace"      # proof nobody is home, or an unfixable advisory in a quiet project
    MITIGATE = "mitigate"    # an advisory with no fix anywhere, but the project is alive
    UPGRADE = "upgrade"      # a newer release clears the advisories against the pinned version
    QUIET = "quiet"          # gone quiet, nothing actually wrong
    UNCHECKED = "unchecked"  # not enough signal - deliberately NOT "bad"
    OK = "ok"                # nothing to do


class Boundary(str, Enum):
    """Which side of the trust boundary the exposure map puts a package on.

    ``UNREVIEWED`` is the honest third answer, and the reason this is not a
    boolean: roughly a quarter of a real dependency set gets no curated call,
    and filing those under "not at a boundary" would state a fact the map
    does not have.
    """

    AT = "at"                  # curated: handles data an attacker can influence
    CLEAR = "clear"            # curated: reviewed, and not at a boundary
    UNREVIEWED = "unreviewed"  # no opinion, or only a classifier guess


#: Ordering used for report sections and for ``--fail-on``.
VERDICT_ORDER = [
    Verdict.EXPLOITED,
    Verdict.REPLACE,
    Verdict.MITIGATE,
    Verdict.UPGRADE,
    Verdict.QUIET,
    Verdict.UNCHECKED,
    Verdict.OK,
]


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
    #: What convinced the curator, when the map records it: the advisory, the
    #: API, or the reason the obvious guess is wrong. Shown so the entry can
    #: be argued with rather than taken on trust.
    why: str | None = None
    #: What a flaw at this boundary tends to cost - "code execution", "denial
    #: of service" - from the category. A word for the reader and a tiebreak
    #: for the report's ordering; never a number and never a verdict.
    consequence: str | None = None

    @property
    def is_exposed(self) -> bool:
        return bool(self.categories)

    @property
    def boundary(self) -> Boundary:
        """Which group the package is reported under.

        A guess is not a review: an inferred category leaves the package
        unreviewed, so nothing built on it can demand action.
        """
        if self.confidence is not Confidence.CURATED:
            return Boundary.UNREVIEWED
        return Boundary.AT if self.categories else Boundary.CLEAR

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

    @property
    def fixed_affecting_current(self) -> int:
        """Advisories against the pinned version that the latest release no
        longer carries: the ones an upgrade would clear."""
        stuck = len(set(self.ids_affecting_current) & set(self.ids_unfixed))
        return max(self.affecting_current - stuck, 0)


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
    #: GitHub's repository-level push time. Any branch, any tag, so it can
    #: only overstate activity; kept for the record and as the fallback.
    repo_last_push: dt.datetime | None = None
    #: The default branch's last commit, when it was fetched. The honest
    #: date, and the one the staleness signal uses when it is known.
    repo_last_commit: dt.datetime | None = None
    inactive_classifier: bool = False
    last_release: dt.datetime | None = None
    #: The earliest upload on PyPI. A package that appeared last week under a
    #: name an agent just invented is the pattern the guardrail exists for.
    first_release: dt.datetime | None = None
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
        """Days since the code last changed: the default branch's last commit
        when known, else the repository-level push time."""
        stamp = self.repo_last_commit or self.repo_last_push
        if stamp is None:
            return None
        return (now - stamp).days


@dataclass(frozen=True)
class Acceptance:
    """A risk the user has decided to carry for now, on the record.

    Every acceptance names a reason and an expiry. Without a reason a
    suppression is indistinguishable from a mistake six months later; without
    an expiry it is permanent, and permanent suppressions are how a known
    exposure survives every review. An expired acceptance stops suppressing
    and the report says so.
    """

    package: str
    reason: str
    until: dt.date
    #: When set, the acceptance applies only while this exact version is
    #: pinned, so an upgrade brings the finding back for a fresh look.
    version: str | None = None
    #: The file it was read from, for the report.
    source: str = ""


@dataclass
class Package:
    name: str
    version: str | None = None
    direct: bool = True
    #: The declared version range when nothing pins an exact version, as
    #: written ("<3,>=2.1"). Used to pick the release a fresh install would get.
    specifier: str | None = None
    #: True when ``version`` was not pinned by the project but assumed from
    #: PyPI: the newest release a fresh install would resolve to. Everything
    #: matched against it is a claim about that assumption, and is shown as one.
    version_assumed: bool = False
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
    #: An acceptance from the project's ``package-doctor.toml`` that names
    #: this package. Set even once expired, so the report can say that the
    #: acceptance ran out rather than silently failing the build again.
    accepted: Acceptance | None = None
    acceptance_expired: bool = False

    @property
    def blocks(self) -> bool:
        """Whether this finding fails a build at the default level.

        Active exploitation blocks wherever it is found. Everything else
        blocks only at a reviewed trust boundary: away from one the same
        facts are worth knowing and not worth stopping a pipeline for, and
        a guessed boundary must never be able to do it.
        """
        if self.verdict is Verdict.EXPLOITED:
            return True
        if self.verdict in (Verdict.REPLACE, Verdict.UPGRADE):
            return self.exposure.boundary is Boundary.AT
        return False

    @property
    def suppressed(self) -> bool:
        """True when an unexpired acceptance covers this finding.

        The verdict is untouched: acceptance is a statement about what the
        user will do, not about the package. It only decides whether the
        finding fails a build and which section of the report it sits in.
        """
        return self.accepted is not None and not self.acceptance_expired
