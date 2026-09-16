"""Per-entry evidence in the exposure map.

An entry that records what convinced the curator can be argued with; a bare
name can only be shrugged at. The map is allowed to carry both forms so it
can grow evidence entry by entry, but three things are enforced: the two
forms load identically, the reason reaches the user, and no new category
entry lands without one.
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from rich.console import Console

from package_doctor.exposure import DATA_FILE, ExposureMap, entries, load_exposure_map
from package_doctor.models import Confidence, Exposure, Finding, Package, Remediation, Verdict
from package_doctor.report import render_explain, to_dict

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

UNEXPLAINED = Path(__file__).parent / "exposure_unexplained.txt"


def _raw() -> dict:
    with DATA_FILE.open("rb") as fh:
        return tomllib.load(fh)


def _unexplained_snapshot() -> set[str]:
    return {
        line.strip()
        for line in UNEXPLAINED.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


# --- the two entry forms ----------------------------------------------------

def test_a_bare_name_and_a_table_load_the_same_way():
    m = ExposureMap({
        "category": {
            "auth": {
                "label": "auth/session",
                "packages": ["plain-one", {"name": "With_Why", "why": "verifies tokens"}],
            }
        }
    })
    assert m.lookup("plain-one").categories == ["auth/session"]
    assert m.lookup("with-why").categories == ["auth/session"]
    assert m.lookup("plain-one").why is None
    assert m.lookup("with-why").why == "verifies tokens"
    assert m.why("With_Why") == "verifies tokens"
    assert m.explained == 1


def test_reviewed_and_stable_entries_carry_their_reason_too():
    m = ExposureMap({
        "reviewed": {"not_exposed": [{"name": "xxhash", "why": "non-cryptographic hash"}]},
        "stable": {
            "packages": [{"name": "six", "why": "finished"}],
            "mature": [],
        },
    })
    safe = m.lookup("xxhash")
    assert not safe.is_exposed and safe.confidence is Confidence.CURATED
    assert safe.why == "non-cryptographic hash"
    assert m.lookup("six").why == "finished"


def test_a_table_without_a_name_is_refused():
    with pytest.raises(ValueError, match="without a name"):
        ExposureMap({"category": {"x": {"label": "x", "packages": [{"why": "no name"}]}}})


def test_blank_reasons_count_as_absent():
    assert entries([{"name": "a", "why": "   "}]) == [("a", None)]
    assert entries(["a", {"name": "b", "why": " because "}]) == [("a", None), ("b", "because")]
    assert entries(None) == []


# --- the reason reaches the user --------------------------------------------

def _finding(name: str) -> Finding:
    m = load_exposure_map()
    return Finding(
        package=Package(name=name, version="1.0"),
        exposure=m.lookup(name),
        remediation=Remediation(),
        verdict=Verdict.MITIGATE,
    )


def test_explain_shows_the_reason(capsys):
    render_explain(Console(width=100, force_terminal=False), _finding("diskcache"))
    out = capsys.readouterr().out
    assert "Why" in out and "unpickles" in out


def test_json_carries_the_reason():
    payload = to_dict([_finding("diskcache")], [], dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc))
    assert "unpickles" in payload["findings"][0]["exposure"]["why"]
    # A bare-name entry serialises the field as null rather than omitting it.
    plain = to_dict([Finding(
        package=Package(name="x"), exposure=Exposure(), remediation=Remediation(),
        verdict=Verdict.OK,
    )], [], dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc))
    assert plain["findings"][0]["exposure"]["why"] is None


# --- the real map -----------------------------------------------------------

def test_every_reviewed_entry_records_why_the_obvious_guess_is_wrong():
    """The reviewed list exists to say "we looked, and here is why it is
    fine". An entry without the second half is just a name that suppresses
    inference, which is the thing the list was built to avoid."""
    raw = _raw()
    missing = [name for name, why in entries(raw["reviewed"]["not_exposed"]) if not why]
    assert not missing, f"reviewed entries with no reason: {missing}"


def test_every_new_category_entry_records_its_evidence():
    """Entries that predate per-entry evidence are listed in
    exposure_unexplained.txt. That file only shrinks: a categorised package
    that is neither explained nor on the list is a new entry added without
    saying what convinced its author, and that is the one thing a curated
    map must not accumulate."""
    raw = _raw()
    from package_doctor.sources.pypi import normalise

    unexplained = {
        normalise(name)
        for block in raw["category"].values()
        for name, why in entries(block["packages"])
        if not why
    }
    allowed = _unexplained_snapshot()
    new_without_reason = sorted(unexplained - allowed)
    assert not new_without_reason, (
        "category entries added without a `why`: "
        f"{new_without_reason}. Use {{ name = \"...\", why = \"...\" }} and say what "
        "convinced you - the advisory, the API, the input it handles."
    )


def test_the_unexplained_snapshot_only_shrinks():
    """A name on the list that now has a reason, or is gone, should be
    removed from the list rather than left to mask a future regression."""
    raw = _raw()
    from package_doctor.sources.pypi import normalise

    explained_or_gone = set(_unexplained_snapshot())
    for block in raw["category"].values():
        for name, why in entries(block["packages"]):
            if not why:
                explained_or_gone.discard(normalise(name))
    assert not explained_or_gone, (
        f"remove from exposure_unexplained.txt, these now have a reason or no entry: "
        f"{sorted(explained_or_gone)}"
    )


def test_the_recorded_reasons_are_the_ones_the_readme_and_tests_cite():
    m = load_exposure_map()
    assert "pickle" in (m.why("apscheduler") or "").lower()
    assert "known-exploited" in (m.why("pillow") or "")
    assert "account compromise" in (m.why("num2words") or "")
    assert m.explained >= 100
