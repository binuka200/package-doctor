"""Axis 2 and the verdict: is anyone home, and does it matter?

The rule that separates this tool from every release-age scanner:

* An **authoritative** signal is proof that nobody is home: the repository is
  archived, or the maintainer set the Inactive classifier. Those are statements
  of fact, and they alone can ask for a replacement.
* A **weak** signal is never enough on its own. Release age in particular is a
  notoriously bad solo signal: it cannot distinguish an abandoned library from
  a finished one, or from a tool whose data updates server-side. Two weak
  signals that agree make a package *quiet*, which is a forecast about who
  would answer - not a reason to migrate off it, and never a failed build.

What the user should do comes from the vulnerabilities against the version in
use crossed with that capacity; the trust boundary decides how loud it is, and
is the only thing that turns a finding into a failed build.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .models import Confidence, Evidence, Exposure, Finding, Package, Remediation, Verdict
from .sources.exploitability import describe as describe_exploit


@dataclass(frozen=True)
class Thresholds:
    #: No release in this long counts as one weak signal.
    stale_release_days: int = 730
    #: No commit pushed in this long counts as one weak signal.
    stale_push_days: int = 545
    #: A median post-disclosure exposure window above this counts as one weak signal.
    slow_fix_days: int = 90
    #: Weak signals required before calling a package unmaintained.
    weak_signals_required: int = 2


def _years(days: int) -> str:
    return f"{days / 365.25:.1f}y"


def _ago(days: int) -> str:
    """A short age for recent events, where "0.0y" would read as a bug."""
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} ago"
    if days < 730:
        months = round(days / 30.44)
        return f"{months} month{'s' if months != 1 else ''} ago"
    return f"{_years(days)} ago"


def _excludes(specifier: str | None, version: str | None) -> bool:
    """True when a declared range rules out a release, so a reinstall cannot reach it."""
    if not specifier or not version:
        return False
    try:
        return not SpecifierSet(specifier).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False


def assess(
    package: Package,
    exposure: Exposure,
    remediation: Remediation,
    *,
    now: dt.datetime,
    thresholds: Thresholds | None = None,
    known_stable: bool = False,
) -> Finding:
    thresholds = thresholds or Thresholds()
    authoritative: list[Evidence] = []
    weak: list[Evidence] = []
    pypi_url = f"https://pypi.org/project/{package.name}/"

    # ---- authoritative: statements of fact -------------------------------
    since_release = remediation.days_since_release(now)
    if remediation.repo_archived is True:
        if since_release is not None and since_release <= thresholds.stale_release_days:
            # The *declared* repository is archived, but releases keep coming,
            # so the code has most likely moved - google-cloud-bigquery's repo
            # was archived when Google folded it into a monorepo, and it ships
            # monthly. The fact is stated, but it is not proof nobody is home,
            # so it counts as one weak signal rather than settling the matter.
            weak.append(
                Evidence(
                    f"declared repository is archived, but a release shipped "
                    f"{_ago(since_release)} - the code may have moved",
                    remediation.repo_url,
                )
            )
        else:
            authoritative.append(
                Evidence("repository is archived", remediation.repo_url)
            )
    if remediation.inactive_classifier:
        authoritative.append(
            Evidence("marked Development Status :: 7 - Inactive by its maintainer", pypi_url)
        )
    adv = remediation.advisories
    exploit = remediation.exploitability
    if exploit.kev:
        # Not a prediction. These have been used against real targets, so this
        # outranks every other signal the tool has.
        ids = ", ".join(exploit.kev[:3])
        authoritative.insert(
            0,
            Evidence(
                f"{ids} on CISA's known-exploited list, and your pinned version is affected",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ),
        )
    unfixed_evidence: list[Evidence] = []
    if adv.unfixed:
        # Weak, not authoritative. Measured across sixty projects, three
        # quarters of the packages this used to condemn were alive and
        # committing: an advisory nobody fixed usually means the maintainer
        # judged that one won't-fix, not that the project is gone. What it
        # costs *you* is decided by whether it affects your version, below.
        ids = ", ".join(adv.ids_unfixed[:2])
        more = f" and {adv.unfixed - 2} more" if adv.unfixed > 2 else ""
        unfixed_evidence.append(
            Evidence(
                f"{adv.unfixed} advisor{'y' if adv.unfixed == 1 else 'ies'} "
                f"with no published fix: {ids}{more}",
                f"https://osv.dev/list?q={package.name}&ecosystem=PyPI",
            )
        )

    # ---- weak: only meaningful in combination ----------------------------
    if since_release is not None and since_release > thresholds.stale_release_days:
        weak.append(
            Evidence(f"no release in {_years(since_release)}", pypi_url)
        )
    since_push = remediation.days_since_push(now)
    if since_push is not None and since_push > thresholds.stale_push_days:
        weak.append(
            Evidence(f"no commits in {_years(since_push)}", remediation.repo_url)
        )
    if adv.late and adv.median_late_days and adv.median_late_days > thresholds.slow_fix_days:
        weak.append(
            Evidence(
                f"{adv.late} of {adv.total} past advisories fixed only after public "
                f"disclosure (median {adv.median_late_days:.0f}d exposed)",
                f"https://osv.dev/list?q={package.name}&ecosystem=PyPI",
            )
        )

    # A reviewed stable utility can still be condemned by an unfixed advisory,
    # but age-based reasoning must not touch it.
    if known_stable:
        weak = []
    # Kept whatever the safelist says: an advisory nobody fixed is a fact about
    # the package, and a reviewed-as-finished entry is a judgement about age.
    weak += unfixed_evidence

    # Proof is a stated fact: the repository is archived, or the maintainer set
    # the Inactive classifier. "Quiet" is an inference from two weak signals
    # agreeing - a forecast about capacity, not evidence that anything is
    # wrong - so it is never on its own a reason to demand a replacement.
    proof = bool(authoritative)
    quiet = len(weak) >= thresholds.weak_signals_required
    signals = authoritative + weak

    # Reachability is evidence, never a verdict.
    #
    # An import site proves the package is in play and is worth showing first.
    # Its absence proves nothing: your dependencies call each other, so a
    # package your code never imports can still run on every request. It
    # therefore raises priority and adds evidence, and never lowers a verdict.
    reach: list[Evidence] = []
    if package.import_sites:
        where = ", ".join(package.import_sites[:2])
        more = f" (+{len(package.import_sites) - 2} more)" if len(package.import_sites) > 2 else ""
        scope = " in test code" if package.imported_in_tests_only else ""
        reach.append(Evidence(f"imported by your code{scope} at {where}{more}"))

    # "Your pinned version is affected" is a fact about the user's situation,
    # not a property of any one verdict path. Building it here rather than
    # inside a branch fixes a real under-report: a package that also trips the
    # abandonment rule used to show only its abandonment reason, hiding that
    # dozens of advisories applied to the version actually installed.
    current: list[Evidence] = []
    # "Upgrade" is only honest when a newer release is actually clear of the
    # advisories: one the latest release still carries is not fixed by moving
    # to it. An assumed version already is the newest a fresh install would
    # get, so there is nothing further to move to unless PyPI says otherwise.
    fixable = adv.fixed_affecting_current
    if package.version_assumed and remediation.latest_version in (None, package.version):
        fixable = 0
    if adv.affecting_current:
        ids = ", ".join(adv.ids_affecting_current[:2])
        more = (
            f" and {adv.affecting_current - 2} more" if adv.affecting_current > 2 else ""
        )
        # An assumed version is a guess about what a fresh install would get,
        # and a claim built on a guess has to say so in the same breath. A
        # range is named when there is one: `nltk<=3.8.1` pins nltk as surely
        # as `==` does, and "nothing pins this package" beside a latest
        # release of 3.10.3 read as a contradiction on huggingface/transformers.
        if not package.version_assumed:
            subject = f"pinned version {package.version}"
        elif package.specifier:
            subject = (
                f"{package.version}, the newest release {package.specifier} allows "
                f"(assumed: no exact pin),"
            )
        else:
            subject = f"newest release {package.version} (assumed: nothing pins this package)"
        current.append(
            Evidence(
                f"{subject} is affected by "
                f"{adv.affecting_current} advisor"
                f"{'y' if adv.affecting_current == 1 else 'ies'}: {ids}{more}",
                f"https://osv.dev/list?q={package.name}&ecosystem=PyPI",
            )
        )
        if fixable:
            # When the project's own range is what holds the fix back, the
            # upgrade is an edit to that range, not a reinstall.
            outside = (
                f" outside {package.specifier}"
                if _excludes(package.specifier, remediation.latest_version)
                else ""
            )
            target = (
                f"the latest release, {remediation.latest_version}{outside},"
                if remediation.latest_version
                else "a newer release"
            )
            if fixable == adv.affecting_current:
                what = "it" if fixable == 1 else "all of them"
            else:
                rest = adv.affecting_current - fixable
                verb = "has" if rest == 1 else "have"
                what = f"{fixable} of them; {rest} {verb} no published fix"
            current.append(Evidence(f"{target} fixes {what}"))
        note = describe_exploit(exploit)
        if note and not exploit.kev:
            current.append(Evidence(note, "https://www.first.org/epss/"))

    # ---- verdict ---------------------------------------------------------
    #
    # Each verdict names what to do, and the first that applies wins. The
    # order is what it costs to ignore: a flaw being exploited today, then a
    # boundary nobody will ever patch, then a patch that already exists.
    reasons: list[Evidence] = []
    unfixable = adv.affecting_current - fixable
    guessed: list[Evidence] = []
    if exposure.is_exposed and exposure.confidence is Confidence.INFERRED:
        guessed.append(
            Evidence(
                f"exposure ({exposure.label}) is inferred from PyPI metadata, not "
                f"reviewed: confirm whether it is at a trust boundary"
            )
        )
    no_signal = (
        remediation.gaps != []
        and remediation.last_release is None
        and remediation.repo_archived is None
        and not adv.has_signal
    )

    if no_signal:
        verdict = Verdict.UNCHECKED
        reasons.append(Evidence("not enough data to judge: " + "; ".join(remediation.gaps)))
    elif exploit.kev:
        # A CVE on CISA's confirmed-exploited-in-the-wild list, affecting the
        # version actually pinned, is not a guess about what the package does -
        # it is a fact that this exact vulnerability has already been used
        # against real targets. It is the one verdict that does not wait on the
        # exposure map, and the one that blocks wherever it is found.
        verdict = Verdict.EXPLOITED
        reasons.extend(signals)
        reasons.extend(current)
        reasons.extend(reach)
    elif proof or (unfixable and quiet):
        # Nobody is home, and this is the evidence rather than the forecast:
        # the repository is archived or marked Inactive, or your version carries
        # an advisory with no fix anywhere and the project has gone quiet. Any
        # upgrade that helps today is still named; it does not change the answer,
        # because the next flaw here will have no fix to upgrade to either.
        verdict = Verdict.REPLACE
        reasons.extend(signals)
        reasons.extend(current)
        reasons.extend(reach)
    elif unfixable:
        # An advisory against your version that no release anywhere fixes, in a
        # project that is still shipping. Upgrading cannot clear it, so the call
        # is a human one - work around it, or press upstream - and a build that
        # cannot be turned green is the fastest way to get a scanner switched
        # off. It never blocks.
        verdict = Verdict.MITIGATE
        reasons.extend(current)
        reasons.extend(signals)
        reasons.extend(guessed)
        reasons.extend(reach)
    elif fixable:
        # Known-vulnerable, and the fix already exists. Cheap to act on, which
        # is why it blocks at a reviewed boundary and only informs away from
        # one: a lockfile a few releases behind is the normal state of a
        # project rather than an emergency.
        verdict = Verdict.UPGRADE
        reasons.extend(current)
        reasons.extend(signals)
        reasons.extend(guessed)
        reasons.extend(reach)
    elif signals:
        # Gone quiet, with nothing actually wrong. Worth knowing before you
        # need a fix - it is a statement about who would answer, not an
        # accusation - so it is never a reason to stop a build.
        verdict = Verdict.QUIET
        reasons.extend(signals)
        if known_stable:
            reasons.append(Evidence("reviewed as a finished utility, not at a trust boundary"))
    elif exposure.confidence is Confidence.NONE:
        verdict = Verdict.UNCHECKED
        reasons.append(Evidence("no exposure signal and no maintenance signal"))
    else:
        # Including a maintained package at a trust boundary. There is nothing
        # to do about it, and a section that asks nothing of the reader is an
        # inventory, not a finding. The exposure is still in `explain` and JSON.
        verdict = Verdict.OK

    return Finding(
        package=package,
        exposure=exposure,
        remediation=remediation,
        verdict=verdict,
        reasons=reasons,
        abandonment_signals=signals,
    )
