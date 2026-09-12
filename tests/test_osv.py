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
    assert h.unfixed == 1  # no fix found *for demo*
    assert h.affecting_current == 0
