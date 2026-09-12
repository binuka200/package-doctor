"""Advisory-history maths, including the backfill trap."""

from __future__ import annotations

import datetime as dt

from package_doctor.sources.osv import _affects_version, build_history


def ts(y: int, m: int = 1, d: int = 1) -> dt.datetime:
    return dt.datetime(y, m, d, tzinfo=dt.timezone.utc)


def vuln(vid: str, published: str | None, fixed: str | None, introduced: str = "0", versions=None):
    affected: dict = {"package": {"name": "demo", "ecosystem": "PyPI"}}
    events: list[dict] = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    affected["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if versions is not None:
        affected["versions"] = versions
    out = {"id": vid, "affected": [affected]}
    if published:
        out["published"] = published
    return out


RELEASES = {"1.0": ts(2020), "1.1": ts(2021), "2.0": ts(2022, 6)}


def test_unfixed_advisory_is_counted_and_identified():
    h = build_history("demo", [vuln("PYSEC-1", "2023-01-01T00:00:00Z", None)], RELEASES, None)
    assert h.unfixed == 1
    assert h.ids_unfixed == ["PYSEC-1"]


def test_fix_before_disclosure_counts_as_timely():
    h = build_history("demo", [vuln("G-1", "2022-07-01T00:00:00Z", "2.0")], RELEASES, None)
    assert (h.timely, h.late) == (1, 0)


def test_backfilled_advisory_does_not_become_a_huge_negative():
    """A 2024 advisory for a 2020 fix is backfill, not a ten-year head start.
    It must land in `timely` and contribute nothing to the late-window median."""
    h = build_history("demo", [vuln("G-old", "2024-01-01T00:00:00Z", "1.0")], RELEASES, None)
    assert h.timely == 1
    assert h.median_late_days is None


def test_late_fix_window_is_measured():
    h = build_history("demo", [vuln("G-2", "2022-01-01T00:00:00Z", "2.0")], RELEASES, None)
    assert h.late == 1
    assert h.median_late_days == 151


def test_fix_version_absent_from_pypi_is_unmatched_not_guessed():
    h = build_history("demo", [vuln("G-3", "2022-01-01T00:00:00Z", "9.9")], RELEASES, None)
    assert h.unmatched == 1
    assert (h.timely, h.late) == (0, 0)


def test_affects_current_version_via_explicit_list():
    v = vuln("G-4", "2022-01-01T00:00:00Z", "2.0", versions=["1.0", "1.1"])
    h = build_history("demo", [v], RELEASES, "1.1")
    assert h.affecting_current == 1
    assert build_history("demo", [v], RELEASES, "2.0").affecting_current == 0


def test_affects_current_version_via_range_when_no_list():
    v = vuln("G-5", "2022-01-01T00:00:00Z", "2.0", introduced="1.0")
    assert _affects_version(v, "demo", "1.5") is True
    assert _affects_version(v, "demo", "2.0") is False
    assert _affects_version(v, "demo", "0.9") is False


def test_unparseable_version_does_not_crash():
    v = vuln("G-6", "2022-01-01T00:00:00Z", "2.0", introduced="1.0")
    assert _affects_version(v, "demo", "not-a-version") is False


def test_advisories_for_other_packages_are_ignored():
    v = {
        "id": "G-7",
        "published": "2022-01-01T00:00:00Z",
        "affected": [{"package": {"name": "somethingelse", "ecosystem": "PyPI"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}],
    }
    h = build_history("demo", [v], RELEASES, "1.0")
    assert h.total == 0, "a record that never names the package says nothing about it"
    assert h.unfixed == 0
    assert h.affecting_current == 0


# --- OSV range semantics: last_affected and open-ended ranges ----------------

def ranged(vid, events, versions=None, aliases=(), published="2022-07-01T00:00:00Z"):
    affected = {"package": {"name": "demo", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if versions is not None:
        affected["versions"] = versions
    return {"id": vid, "published": published, "aliases": list(aliases), "affected": [affected]}


def test_last_affected_closes_the_range_inclusively():
    """GitHub encodes most older fixes this way. Django's 2011 CSRF advisory is
    introduced 0, last_affected 1.2.7 - and Django 6 is not affected by it."""
    v = ranged("GHSA-la", [{"introduced": "0"}, {"last_affected": "1.2.7"}])
    assert _affects_version(v, "demo", "1.2.7") is True
    assert _affects_version(v, "demo", "1.2.6") is True
    assert _affects_version(v, "demo", "1.2.8") is False
    assert _affects_version(v, "demo", "6.1") is False


def test_an_open_ended_range_affects_every_later_version():
    """scrapy's PYSEC-2017-83 is `introduced: 0.7` and nothing else. OSV's own
    query reports 2.17.0 as affected; a matcher waiting for `fixed` never did."""
    v = ranged("PYSEC-open", [{"introduced": "0.7"}])
    assert _affects_version(v, "demo", "2.17.0") is True
    assert _affects_version(v, "demo", "0.6") is False


def test_a_second_introduced_reopens_after_a_close_and_leaves_the_first_open():
    v = ranged("G-multi", [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}])
    assert _affects_version(v, "demo", "1.2") is True
    assert _affects_version(v, "demo", "1.7") is False
    assert _affects_version(v, "demo", "3.0") is True
    v2 = ranged("G-noclose", [{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.5"}])
    assert _affects_version(v2, "demo", "1.5") is True, "the first range was never closed"


# --- "never fixed" means the latest release is still affected ---------------

def test_last_affected_before_the_latest_release_is_bounded_not_unfixed():
    """No fix is named, but every current version is outside the range. That
    is not evidence nobody is home, and it was the source of 36 wrong
    escalations in the field."""
    v = ranged("GHSA-la", [{"introduced": "0"}, {"last_affected": "1.2.7"}])
    h = build_history("demo", [v], RELEASES, "6.1", latest_version="6.1")
    assert (h.unfixed, h.bounded, h.affecting_current) == (0, 1, 0)
    assert h.ids_unfixed == []


def test_last_affected_at_the_latest_release_is_unfixed():
    v = ranged("GHSA-la", [{"introduced": "0"}, {"last_affected": "2.0"}])
    h = build_history("demo", [v], RELEASES, "2.0", latest_version="2.0")
    assert (h.unfixed, h.bounded, h.affecting_current) == (1, 0, 1)


def test_an_open_ended_range_is_unfixed_whatever_the_latest_release():
    v = ranged("PYSEC-open", [{"introduced": "0.7"}])
    assert build_history("demo", [v], RELEASES, "2.0", latest_version="2.0").unfixed == 1
    assert build_history("demo", [v], RELEASES, "2.0").unfixed == 1, "fallback: no latest known"


def test_a_malicious_version_record_is_not_an_unfixed_advisory():
    """MAL-* records list the versions that carried malicious code. They mean
    "do not install 1.5", not "nobody ever fixed this"."""
    mal = {"id": "MAL-2026-1", "published": "2026-04-30T00:00:00Z",
           "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}, "versions": ["1.5"]}]}
    h = build_history("demo", [mal], RELEASES, "2.0", latest_version="2.0")
    assert (h.unfixed, h.affecting_current) == (0, 0)
    h = build_history("demo", [mal], RELEASES, "1.5", latest_version="2.0")
    assert h.affecting_current == 1, "but the listed version is affected"


def test_a_versions_list_that_includes_the_latest_release_is_unfixed():
    only = {"id": "GHSA-list", "published": "2026-06-16T00:00:00Z",
            "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"},
                          "versions": ["1.1", "2.0"]}]}
    assert build_history("demo", [only], RELEASES, None, latest_version="2.0").unfixed == 1


def test_a_fixed_range_reopened_later_is_unfixed():
    """Fixed in 1.5, reintroduced in 2.0 with no fix: the latest is affected."""
    v = ranged("G-regress", [{"introduced": "0"}, {"fixed": "1.5"}, {"introduced": "2.0"}])
    h = build_history("demo", [v], RELEASES, "2.0", latest_version="2.0")
    assert h.unfixed == 1


# --- one CVE, one advisory ---------------------------------------------------

def test_ghsa_and_pysec_records_of_one_cve_count_once():
    """cryptography 46.0.7 read as "affected by 7 advisories"; it was four."""
    ghsa = ranged("GHSA-aaaa", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2026-1"])
    pysec = ranged("PYSEC-2026-9", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2026-1"])
    other = ranged("GHSA-bbbb", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2026-2"])
    h = build_history("demo", [pysec, ghsa, other], RELEASES, "1.0", latest_version="2.0")
    assert h.total == 2
    assert h.affecting_current == 2
    assert h.ids_affecting_current == ["GHSA-aaaa", "GHSA-bbbb"], "GHSA preferred as the name"
    assert h.cves_affecting_current == ["CVE-2026-1", "CVE-2026-2"]
    assert h.timely == 2


def test_merged_records_pool_their_evidence():
    """If either record names a fix, the vulnerability was fixed; if either
    record's range covers the pinned version, it is affected."""
    bare = ranged("PYSEC-2026-9", [{"introduced": "0"}, {"last_affected": "1.1"}],
                  aliases=["CVE-2026-1"])
    fixed = ranged("GHSA-aaaa", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2026-1"])
    h = build_history("demo", [bare, fixed], RELEASES, "1.1", latest_version="2.0")
    assert (h.total, h.affecting_current, h.timely, h.unfixed, h.bounded) == (1, 1, 1, 0, 0)


def test_records_without_a_cve_are_never_merged():
    a = ranged("GHSA-aaaa", [{"introduced": "0"}, {"fixed": "2.0"}])
    b = ranged("GHSA-bbbb", [{"introduced": "0"}, {"fixed": "2.0"}])
    assert build_history("demo", [a, b], RELEASES, "1.0", latest_version="2.0").total == 2
