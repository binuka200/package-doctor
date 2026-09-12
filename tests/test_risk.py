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
