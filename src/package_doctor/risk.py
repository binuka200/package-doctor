"""Axis 2 and the verdict: is anyone home, and does it matter?

The rule that separates this tool from every release-age scanner:

* An **authoritative** signal alone is enough to call a package unmaintained.
  These are statements of fact, not inferences - the repository is archived,
  the maintainer set the Inactive classifier, or an advisory exists with no
  patched release anywhere.
* A **weak** signal is never enough on its own. Release age in particular is a
  notoriously bad solo signal: it cannot distinguish an abandoned library from
  a finished one, or from a tool whose data updates server-side. Two weak
  signals that agree are required before the tool will say anything.

And a package is only ever escalated to "act on this" when the unmaintained
finding meets a trust boundary.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

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


def assess(
    package: Package,
    exposure: Exposure,
    remediation: Remediation,
    *,
    now: dt.datetime,
    thresholds: Thresholds = Thresholds(),
    known_stable: bool = False,
) -> Finding:
    authoritative: list[Evidence] = []
    weak: list[Evidence] = []
    pypi_url = f"https://pypi.org/project/{package.name}/"

    # ---- authoritative: statements of fact -------------------------------
    if remediation.repo_archived is True:
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
    if adv.unfixed:
        ids = ", ".join(adv.ids_unfixed[:2])
        more = f" and {adv.unfixed - 2} more" if adv.unfixed > 2 else ""
        authoritative.append(
            Evidence(
                f"{adv.unfixed} advisor{'y' if adv.unfixed == 1 else 'ies'} with no published fix: {ids}{more}",
                f"https://osv.dev/list?q={package.name}&ecosystem=PyPI",
            )
        )

    # ---- weak: only meaningful in combination ----------------------------
    since_release = remediation.days_since_release(now)
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

    unmaintained = bool(authoritative) or len(weak) >= thresholds.weak_signals_required
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
    if adv.affecting_current:
        ids = ", ".join(adv.ids_affecting_current[:2])
        more = (
            f" and {adv.affecting_current - 2} more" if adv.affecting_current > 2 else ""
        )
        current.append(
            Evidence(
                f"pinned version {package.version} is affected by "
                f"{adv.affecting_current} advisor"
                f"{'y' if adv.affecting_current == 1 else 'ies'}: {ids}{more}",
                f"https://osv.dev/list?q={package.name}&ecosystem=PyPI",
            )
        )
        note = describe_exploit(exploit)
        if note and not exploit.kev:
            current.append(Evidence(note, "https://www.first.org/epss/"))

    # ---- verdict ---------------------------------------------------------
    reasons: list[Evidence] = []
    no_signal = (
        not remediation.gaps == []
        and remediation.last_release is None
        and remediation.repo_archived is None
        and not adv.has_signal
    )

    if no_signal:
        verdict = Verdict.UNKNOWN
        reasons.append(Evidence("not enough data to judge: " + "; ".join(remediation.gaps)))
    elif (
        exposure.is_exposed
        and exposure.confidence is Confidence.CURATED
        and (unmaintained or adv.affecting_current)
    ):
        # Either nobody is left to fix it, or the version installed right now
        # is known-vulnerable. Both are actionable and both get stated.
        #
        # Only a *curated* exposure can reach this branch. An inferred category
        # is a guess, measured at roughly 40% accurate, and a guess must never
        # be able to demand action - it can raise something to WATCH and say
        # why, and that is all.
        verdict = Verdict.ACT
        reasons.extend(signals)
        reasons.extend(current)
        reasons.extend(reach)
    elif exposure.is_exposed:
        verdict = Verdict.WATCH
        if adv.timely:
            reasons.append(
                Evidence(
                    f"{adv.timely} of {adv.total} past advisories fixed at or before disclosure"
                )
            )
        reasons.extend(signals)
        reasons.extend(reach)
        if not reasons:
            # Exposed but nothing adverse found. Say so explicitly rather than
            # leaving a blank cell - and say what we do *not* know, since an
            # empty security record is absence of evidence, not evidence of care.
            if not adv.has_signal:
                reasons.append(
                    Evidence("at a trust boundary; no advisory history to judge it by")
                )
            else:
                reasons.append(Evidence("at a trust boundary; no maintenance concerns found"))
    elif signals or current:
        # Not at a known trust boundary, so this is an observation rather than
        # an accusation. A single weak signal is enough to mention it here,
        # because nothing in this bucket asks the user to do anything.
        #
        # `current` belongs in the condition, not just the body: a package whose
        # installed version has published advisories must never report OK just
        # because it is maintained and absent from the exposure map. Coverage of
        # the map is incomplete by design, and this is what stops that gap from
        # turning into silence about a known-vulnerable version.
        verdict = Verdict.LOW
        reasons.extend(signals)
        reasons.extend(current)
        if known_stable:
            reasons.append(Evidence("reviewed as a finished utility, not at a trust boundary"))
    elif exposure.confidence is Confidence.NONE:
        verdict = Verdict.UNKNOWN
        reasons.append(Evidence("no exposure signal and no maintenance signal"))
    else:
        verdict = Verdict.OK

    return Finding(
        package=package,
        exposure=exposure,
        remediation=remediation,
        verdict=verdict,
        reasons=reasons,
        abandonment_signals=signals,
    )
