"""The rules that stop this tool becoming another release-age scanner."""

from __future__ import annotations

import datetime as dt

import pytest

from package_doctor.models import (
    AdvisoryHistory,
    Confidence,
    Exposure,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.risk import assess

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
    assert finding.verdict is not Verdict.REPLACE


def test_two_weak_signals_agreeing_is_quiet_not_a_replacement():
    """Quiet for years is a forecast about capacity, not evidence that anything
    is wrong. Measured on sixty projects, three quarters of the packages this
    used to condemn had nothing against the version in use."""
    rem = Remediation(last_release=years_ago(5), repo_last_push=years_ago(4), repo_archived=False)
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.QUIET
    assert not finding.blocks


def test_archived_repo_alone_is_enough():
    """With no release inside the stale window; see the moved-code tests for
    an archived repository that is still shipping."""
    rem = healthy(repo_archived=True, last_release=years_ago(3))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.REPLACE
    assert any("archived" in r.claim for r in finding.reasons)


def test_inactive_classifier_alone_is_enough():
    finding = assess(pkg(), exposed(), healthy(inactive_classifier=True), now=NOW)
    assert finding.verdict is Verdict.REPLACE


def test_an_unfixed_advisory_that_misses_your_version_is_only_a_signal():
    """It is stated, but nothing is wrong with the version in use, and the
    project is still shipping."""
    rem = healthy(advisories=AdvisoryHistory(total=3, unfixed=1, ids_unfixed=["PYSEC-1"]))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.QUIET
    assert any("no published fix" in r.claim for r in finding.reasons)


# --- the two-axis rule ------------------------------------------------------

def test_unmaintained_but_not_exposed_is_not_actionable():
    """`six` going quiet must never look like `legacy-auth` going quiet."""
    rem = Remediation(last_release=years_ago(6), repo_last_push=years_ago(5), repo_archived=False)
    finding = assess(pkg("six"), not_exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.QUIET


def test_exposed_and_maintained_asks_nothing():
    finding = assess(pkg(), exposed(), healthy(), now=NOW)
    assert finding.verdict is Verdict.OK


def test_known_stable_suppresses_age_signals():
    rem = Remediation(last_release=years_ago(8), repo_last_push=years_ago(7), repo_archived=False)
    finding = assess(pkg("six"), not_exposed(), rem, now=NOW, known_stable=True)
    assert finding.verdict is not Verdict.REPLACE
    assert not any("no release" in r.claim for r in finding.reasons)


def test_known_stable_does_not_suppress_an_unfixed_advisory():
    """A safelist entry is a judgement about age, not a licence to ignore facts."""
    rem = healthy(advisories=AdvisoryHistory(total=1, unfixed=1, ids_unfixed=["PYSEC-9"]))
    finding = assess(pkg("six"), exposed(), rem, now=NOW, known_stable=True)
    assert any("no published fix" in r.claim for r in finding.reasons)
    assert finding.verdict is Verdict.QUIET


# --- live exposure ----------------------------------------------------------

def test_pinned_vulnerable_version_is_an_upgrade_even_when_maintained():
    rem = healthy(
        advisories=AdvisoryHistory(total=5, timely=5, affecting_current=2,
                                   ids_affecting_current=["GHSA-a", "GHSA-b"])
    )
    finding = assess(pkg(version="1.0.0"), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.UPGRADE
    assert any("pinned version" in r.claim for r in finding.reasons)


# --- missing data -----------------------------------------------------------

def test_no_signal_is_unknown_never_bad():
    rem = Remediation(gaps=["no source repository declared on PyPI"])
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.UNCHECKED


def test_clean_record_is_ok():
    finding = assess(pkg(), not_exposed(), healthy(), now=NOW)
    assert finding.verdict is Verdict.OK


def test_every_reason_is_a_sentence_not_a_score():
    finding = assess(pkg(), exposed(), healthy(repo_archived=True), now=NOW)
    assert finding.reasons
    for reason in finding.reasons:
        assert reason.claim and not reason.claim.strip().isdigit()


@pytest.mark.parametrize("days,expected", [(100, Verdict.QUIET), (2000, Verdict.QUIET)])
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
    assert finding.verdict is Verdict.UPGRADE
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
    packages reviewed as NOT exposed. A guess may raise something to REVIEW and
    explain itself; it must not be able to demand a replacement."""
    guessed = Exposure(categories=["http/network"], confidence=Confidence.INFERRED)
    rem = healthy(repo_archived=True, last_release=years_ago(3),
                  advisories=AdvisoryHistory(total=2, unfixed=1, ids_unfixed=["GHSA-a"],
                                             affecting_current=1,
                                             ids_affecting_current=["GHSA-a"]))
    guess = assess(pkg(), guessed, rem, now=NOW)
    reviewed = assess(pkg(), exposed(), rem, now=NOW)
    # The facts are the same, so the verdict is; what a guess cannot do is
    # fail somebody's build.
    assert guess.verdict is reviewed.verdict is Verdict.REPLACE
    assert not guess.blocks and reviewed.blocks


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


# --- an archived repository that keeps releasing -----------------------------

def test_an_archived_repo_with_a_recent_release_is_a_weak_signal_not_proof():
    """google-cloud-bigquery's declared repo is archived because Google moved
    it into a monorepo; it ships monthly. The fact is stated, but it cannot
    settle "nobody is home" on its own."""
    rem = healthy(repo_archived=True, last_release=years_ago(0.1))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.QUIET
    claims = [e.claim for e in finding.abandonment_signals]
    assert any("may have moved" in c for c in claims)
    assert "repository is archived" not in claims


def test_an_archived_repo_with_no_recent_release_is_authoritative():
    rem = healthy(repo_archived=True, last_release=years_ago(3), repo_last_push=years_ago(3))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.REPLACE
    assert "repository is archived" in [e.claim for e in finding.abandonment_signals]


def test_an_archived_repo_with_unknown_release_date_stays_authoritative():
    """Missing data must not soften a stated fact."""
    rem = Remediation(repo_archived=True, last_release=None)
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.REPLACE


def test_moved_and_stale_together_are_quiet():
    """Archived-but-releasing plus a second weak signal is two weak signals,
    which is quiet rather than proof that nobody is home."""
    rem = healthy(repo_archived=True, last_release=years_ago(0.5), repo_last_push=years_ago(3))
    assert assess(pkg(), exposed(), rem, now=NOW).verdict is Verdict.QUIET


def test_recent_ages_are_worded_in_days_or_months_not_zero_years():
    from package_doctor.risk import _ago
    assert _ago(0) == "0 days ago"
    assert _ago(1) == "1 day ago"
    assert _ago(12) == "12 days ago"
    assert _ago(95) == "3 months ago"
    assert _ago(800) == "2.2y ago"
    rem = healthy(repo_archived=True, last_release=years_ago(0.02))
    claims = [e.claim for e in assess(pkg(), exposed(), rem, now=NOW).abandonment_signals]
    assert any("days ago" in c for c in claims) and not any("0.0y" in c for c in claims)


# --- verdicts named for the action ------------------------------------------

def test_a_fix_at_a_reviewed_boundary_is_an_upgrade_and_elsewhere_a_bump():
    rem = healthy(latest_version="2.4.0", advisories=AdvisoryHistory(
        total=2, affecting_current=2, ids_affecting_current=["GHSA-a", "GHSA-b"]))
    upgrade = assess(pkg(), exposed(), rem, now=NOW)
    assert upgrade.verdict is Verdict.UPGRADE
    assert "the latest release, 2.4.0, fixes all of them" in [r.claim for r in upgrade.reasons]
    assert assess(pkg(), not_exposed(), rem, now=NOW).verdict is Verdict.UPGRADE
    # A guessed boundary may not demand action, so it is a bump, and says why.
    guessed = Exposure(categories=["http/network"], confidence=Confidence.INFERRED)
    bump = assess(pkg(), guessed, rem, now=NOW)
    assert bump.verdict is Verdict.UPGRADE
    assert any("inferred from PyPI metadata" in r.claim for r in bump.reasons)


def test_a_partial_fix_away_from_a_boundary_is_for_review_and_says_what_it_clears():
    rem = healthy(latest_version="2.4.0", advisories=AdvisoryHistory(
        total=3, affecting_current=2, ids_affecting_current=["GHSA-a", "GHSA-b"],
        unfixed=1, ids_unfixed=["GHSA-b"]))
    finding = assess(pkg(), not_exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.MITIGATE
    claims = [r.claim for r in finding.reasons]
    assert "the latest release, 2.4.0, fixes 1 of them; 1 has no published fix" in claims


def test_advisories_with_no_fix_to_upgrade_to_are_for_review():
    rem = healthy(advisories=AdvisoryHistory(
        total=1, affecting_current=1, ids_affecting_current=["GHSA-a"],
        unfixed=1, ids_unfixed=["GHSA-a"]))
    assert assess(pkg(), not_exposed(), rem, now=NOW).verdict is Verdict.MITIGATE
    # The project is alive, so this is a won't-fix to work around, wherever it
    # sits. It becomes a replacement only once the project has gone quiet too.
    assert assess(pkg(), exposed(), rem, now=NOW).verdict is Verdict.MITIGATE
    gone = assess(pkg(), exposed(), healthy(
        last_release=years_ago(4), repo_last_push=years_ago(4),
        advisories=rem.advisories), now=NOW)
    assert gone.verdict is Verdict.REPLACE


def test_replace_outranks_upgrade_but_still_names_the_upgrade():
    rem = healthy(repo_archived=True, last_release=years_ago(3), latest_version="1.2.0",
                  advisories=AdvisoryHistory(total=1, affecting_current=1,
                                             ids_affecting_current=["GHSA-a"]))
    finding = assess(pkg(), exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.REPLACE
    assert "the latest release, 1.2.0, fixes it" in [r.claim for r in finding.reasons]


def test_an_assumed_newest_version_has_nothing_to_upgrade_to():
    rem = healthy(advisories=AdvisoryHistory(total=1, affecting_current=1,
                                             ids_affecting_current=["GHSA-a"]))
    assumed = Package(name="thing", version="1.0.0", version_assumed=True)
    finding = assess(assumed, not_exposed(), rem, now=NOW)
    assert finding.verdict is Verdict.MITIGATE
    assert not any("fixes" in r.claim for r in finding.reasons)
