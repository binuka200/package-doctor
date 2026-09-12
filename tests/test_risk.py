"""The rules that stop this tool becoming another release-age scanner."""

from __future__ import annotations

import datetime as dt

import pytest

from package_doctor.models import (
    AdvisoryHistory, Confidence, Exposure, Package, Remediation, Verdict,
)
from package_doctor.risk import Thresholds, assess

NOW = dt.datetime(2026, 9, 12, tzinfo=dt.timezone.utc)


def years_ago(n: float) -> dt.datetime:
    return NOW - dt.timedelta(days=int(365.25 * n))


def pkg(name: str = "thing", version: str | None = "1.0.0") -> Package:
    return Package(name=name, version=version)


def exposed(*cats: str) -> Exposure:
    return Exposure(categories=list(cats) or ["auth/session"], confidence=Confidence.CURATED)


def not_exposed() -> Exposure:
    return Exposure(categories=[], confidence=Confidence.CURATED)


def healthy(**kw) -> Remediation:
    base = dict(last_release=years_ago(0.2), repo_archived=False, repo_last_push=years_ago(0.1))
    base.update(kw)
    return Remediation(**base)


# --- the central rule -------------------------------------------------------

def test_stale_alone_is_never_enough():
    """One weak signal must not produce a finding. This is the single most
    common defect in package-health tools."""
    rem = Remediation(last_release=years_ago(5), repo_archived=False, repo_last_push=years_ago(0.1))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is not Verdict.ACT


def test_two_weak_signals_agreeing_is_enough():
    rem = Remediation(last_release=years_ago(5), repo_last_push=years_ago(4), repo_archived=False)
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.ACT


def test_archived_repo_alone_is_enough():
    rem = healthy(repo_archived=True)
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.ACT
    assert any("archived" in r.claim for r in finding.reasons)


def test_inactive_classifier_alone_is_enough():
    finding = assess(pkg(), exposed(), healthy(inactive_classifier=True), now=NOW)
    assert finding.verdict is Verdict.ACT


def test_unfixed_advisory_alone_is_enough():
    rem = healthy(advisories=AdvisoryHistory(total=3, unfixed=1, ids_unfixed=["PYSEC-1"]))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.ACT


# --- the two-axis rule ------------------------------------------------------

def test_unmaintained_but_not_exposed_is_not_actionable():
    """`six` going quiet must never look like `legacy-auth` going quiet."""
    rem = Remediation(last_release=years_ago(6), repo_last_push=years_ago(5), repo_archived=False)
    finding = assess(pkg("six"), not_exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.LOW


def test_exposed_and_maintained_is_watch_not_act():
    finding = assess(pkg(), exposed(), healthy(), now=NOW)
    assert finding.verdict is Verdict.WATCH


def test_known_stable_suppresses_age_signals():
    rem = Remediation(last_release=years_ago(8), repo_last_push=years_ago(7), repo_archived=False)
    finding = assess(pkg("six"), not_exposed(), rem, now=NOW, known_stable=True)
    assert finding.verdict is not Verdict.ACT
    assert not any("no release" in r.claim for r in finding.reasons)


def test_known_stable_does_not_suppress_an_unfixed_advisory():
    """A safelist entry is a judgement about age, not a licence to ignore facts."""
    rem = healthy(advisories=AdvisoryHistory(total=1, unfixed=1, ids_unfixed=["PYSEC-9"]))
    finding = assess(pkg("six"), exposed(), rem, now=NOW, known_stable=True)
    assert finding.verdict is Verdict.ACT


# --- live exposure ----------------------------------------------------------

def test_pinned_vulnerable_version_escalates_even_when_maintained():
    rem = healthy(
        advisories=AdvisoryHistory(total=5, timely=5, affecting_current=2,
                                   ids_affecting_current=["GHSA-a", "GHSA-b"])
    )
    finding = assess(pkg(version="1.0.0"), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.ACT
    assert any("pinned version" in r.claim for r in finding.reasons)


# --- missing data -----------------------------------------------------------

def test_no_signal_is_unknown_never_bad():
    rem = Remediation(gaps=["no source repository declared on PyPI"])
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.UNKNOWN


def test_clean_record_is_ok():
    finding = assess(pkg(), not_exposed(), healthy(), now=NOW)
    assert finding.verdict is Verdict.OK


def test_every_reason_is_a_sentence_not_a_score():
    finding = assess(pkg(), exposed(), healthy(repo_archived=True), now=NOW)
    assert finding.reasons
    for reason in finding.reasons:
        assert reason.claim and not reason.claim.strip().isdigit()


@pytest.mark.parametrize("days,expected", [(100, Verdict.WATCH), (2000, Verdict.WATCH)])
def test_slow_fix_history_alone_does_not_escalate(days, expected):
    rem = healthy(advisories=AdvisoryHistory(total=4, late=2, timely=2, median_late_days=days))
    assert assess(pkg(), exposed(), rem, now=NOW).verdict is expected


# --- regressions found by scanning a real repository ------------------------

def test_an_unmaintained_package_still_reports_its_affected_version():
    """Found on a real Django project: django 4.2.7 tripped the abandonment
    rule via one unfixed advisory, and the report showed only that - silently
    dropping the 83 advisories that applied to the installed version. The user
    would have badly under-estimated their exposure."""
    rem = healthy(
        repo_archived=True,
        advisories=AdvisoryHistory(
            total=321, unfixed=1, ids_unfixed=["GHSA-unfixed"],
            affecting_current=83,
            ids_affecting_current=[f"GHSA-{i}" for i in range(83)],
        ),
    )
    finding = assess(pkg("django", "4.2.7"), exposed("web framework"), rem, now=NOW)
    assert finding.verdict is Verdict.ACT
    claims = " ".join(r.claim for r in finding.reasons)
    assert "no published fix" in claims, "lost the abandonment reason"
    assert "83 advisories" in claims, "lost the affected-version reason"


def test_a_package_outside_the_exposure_map_still_reports_live_advisories():
    """The same omission in the low-priority bucket: not being at a known trust
    boundary is no reason to hide that the installed version is affected."""
    rem = Remediation(
        last_release=years_ago(3),
        repo_last_push=years_ago(3),
        advisories=AdvisoryHistory(
            total=10, affecting_current=4, ids_affecting_current=["GHSA-a", "GHSA-b"]
        ),
    )
    finding = assess(pkg("obscure"), not_exposed(), rem, now=NOW)
    assert "4 advisories" in " ".join(r.claim for r in finding.reasons)


def test_advisory_ids_are_listed_before_the_overflow_count():
    """Two ids is enough to look something up; the count carries the rest."""
    rem = healthy(advisories=AdvisoryHistory(
        total=9, affecting_current=9,
        ids_affecting_current=[f"GHSA-{i}" for i in range(9)]))
    claims = " ".join(r.claim for r in assess(pkg(), exposed(), rem, now=NOW).reasons)
    assert "GHSA-0, GHSA-1 and 7 more" in claims


def test_an_inferred_exposure_can_never_demand_action():
    """Measured against 3,000 packages, classifier inference carried no signal:
    packages it called exposed had advisories at 11.3% against 12.1% for
    packages reviewed as NOT exposed. A guess may raise something to WATCH and
    explain itself; it must not be able to produce an ACT verdict."""
    guessed = Exposure(categories=["http/network"], confidence=Confidence.INFERRED)
    rem = healthy(repo_archived=True,
                  advisories=AdvisoryHistory(total=2, unfixed=1, ids_unfixed=["PYSEC-1"],
                                             affecting_current=3,
                                             ids_affecting_current=["GHSA-a"]))
    assert assess(pkg(), guessed, rem, now=NOW).verdict is Verdict.WATCH
    # The same evidence with a human-reviewed category is actionable.
    assert assess(pkg(), exposed(), rem, now=NOW).verdict is Verdict.ACT


def test_a_known_vulnerable_version_is_never_reported_as_ok():
    """Found on real projects: black and awscli reported OK while carrying
    three and four advisories against the pinned version. Both are maintained
    and neither is in the exposure map, so no rule caught them.

    Map coverage is incomplete by design - roughly half of a real dependency
    set gets no curated call - so a gap in it must never become silence about
    a version with published advisories."""
    rem = healthy(advisories=AdvisoryHistory(
        total=5, timely=5, affecting_current=3,
        ids_affecting_current=["GHSA-a", "GHSA-b", "GHSA-c"]))
    finding = assess(pkg("some-tool"), not_exposed(), rem, now=NOW)
    assert finding.verdict is not Verdict.OK
    assert any("3 advisories" in r.claim for r in finding.reasons)


def test_a_clean_unmapped_package_is_still_ok():
    """The rule above must not make everything noisy: no advisories against the
    installed version and no maintenance signals is genuinely fine."""
    assert assess(pkg(), not_exposed(), healthy(), now=NOW).verdict is Verdict.OK
