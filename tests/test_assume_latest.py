"""Unpinned packages: what a fresh install would get, labelled as a guess.

A project with no lockfile used to get "advisory matching skipped" for every
package, which is a thin first run. Now the newest release a fresh install
would resolve to stands in for the pin - and because it is an assumption,
every place it shows says so. The tests here guard both halves: the choice
is pip's (highest version, not newest upload, yanked and pre-releases out,
declared range honoured) and the label never goes missing.
"""

from __future__ import annotations

import datetime as dt

import pytest
from rich.console import Console

from package_doctor.models import (
    AdvisoryHistory,
    Confidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.parsers.discovery import DependencySet, parse_pyproject, parse_requirements_txt
from package_doctor.report import render, render_explain, render_markdown, to_dict
from package_doctor.risk import assess
from package_doctor.sources.pypi import PyPISource

NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)


def releases(*versions: str, yanked: tuple[str, ...] = ()) -> dict:
    return {
        "info": {},
        "releases": {
            v: [{"upload_time_iso_8601": "2026-01-01T00:00:00Z", "yanked": v in yanked}]
            for v in versions
        },
    }


# --- choosing the version ---------------------------------------------------

def test_the_highest_version_wins_not_the_latest_upload():
    data = releases("4.2.0", "5.0.0", "4.2.1")
    assert PyPISource.newest_matching(data) == "5.0.0"


def test_yanked_and_pre_releases_are_skipped_as_pip_skips_them():
    data = releases("1.0", "1.1", "2.0rc1", "1.2.dev1", yanked=("1.1",))
    assert PyPISource.newest_matching(data) == "1.0"


def test_a_declared_range_is_honoured():
    data = releases("3.2.0", "4.2.0", "5.0.0")
    assert PyPISource.newest_matching(data, "<5") == "4.2.0"
    assert PyPISource.newest_matching(data, ">=3,<4") == "3.2.0"


def test_a_range_nothing_satisfies_returns_none_rather_than_guessing():
    assert PyPISource.newest_matching(releases("1.0", "2.0"), ">=9") is None


def test_an_unparseable_range_or_version_is_ignored_not_fatal():
    data = releases("1.0", "not-a-version")
    assert PyPISource.newest_matching(data, "@@@") == "1.0"


def test_no_releases_means_no_assumption():
    assert PyPISource.newest_matching({"releases": {}}) is None


# --- the parsers keep the range ---------------------------------------------

def test_requirements_ranges_are_kept_for_names_without_a_pin(tmp_path):
    deps = DependencySet()
    path = tmp_path / "requirements.txt"
    parse_requirements_txt(path, deps, "django>=4,<5\nrequests==2.31\nflask\n")
    assert deps.versions == {"django": None, "requests": "2.31", "flask": None}
    # packaging normalises the order of the clauses; the meaning is the same.
    assert deps.specifiers == {"django": "<5,>=4"}


def test_pyproject_ranges_are_kept(tmp_path):
    deps = DependencySet()
    parse_pyproject(tmp_path / "pyproject.toml", deps,
                    '[project]\nname="p"\ndependencies=["httpx>=0.27", "rich==13"]\n')
    assert deps.specifiers == {"httpx": ">=0.27"}


def test_the_first_range_seen_stands(tmp_path):
    deps = DependencySet()
    parse_requirements_txt(tmp_path / "a.txt", deps, "x<3\n")
    parse_requirements_txt(tmp_path / "b.txt", deps, "x>=1\n")
    assert deps.specifiers == {"x": "<3"}


# --- the analyzer applies it ------------------------------------------------

def analyzer(pypi, assume=True):
    """An Analyzer with every source stubbed, and only the version choice real.

    Built here rather than imported from test_analysis: test modules are not
    importable by name under a plain ``pytest`` invocation, which is what CI
    runs, even though ``python -m pytest`` happens to allow it.
    """
    from package_doctor.analysis import Analyzer
    from package_doctor.exposure import load_exposure_map
    from package_doctor.models import Exploitability
    from package_doctor.risk import Thresholds
    from package_doctor.sources.ecosystems import RepoInfo

    a = Analyzer.__new__(Analyzer)
    a.exposure_map = load_exposure_map()
    a.thresholds = Thresholds()
    a.skip_repo = False
    a.assume_latest = assume

    class P:
        async def fetch(self, name):
            return pypi
        release_dates = staticmethod(lambda d: {})
        last_release = staticmethod(lambda d: ("5.0.0", NOW))
        last_upload = staticmethod(lambda d: ("5.0.0", NOW))
        has_inactive_classifier = staticmethod(lambda d: False)
        newest_matching = staticmethod(PyPISource.newest_matching)

    class Osv:
        async def fetch(self, name):
            return []

    class R:
        async def fetch_repo(self, slug):
            return RepoInfo(found=False)

        async def last_commit(self, slug, branch):
            return None

        async def resolve_rename(self, slug):
            return None

    class E:
        async def assess(self, cves):
            return Exploitability()

        async def kev_catalogue(self):
            return frozenset()

    a.pypi, a.osv, a.repos, a.exploit = P(), Osv(), R(), E()
    return a


@pytest.mark.asyncio
async def test_an_unpinned_package_gets_the_newest_matching_release():
    a = analyzer(releases("4.2.0", "5.0.0"))
    pkg = Package(name="pyjwt", version=None, specifier="<5")
    finding = await a.analyze(pkg, NOW)
    assert finding.package.version == "4.2.0"
    assert finding.package.version_assumed is True


@pytest.mark.asyncio
async def test_a_pinned_package_is_never_touched():
    a = analyzer(releases("4.2.0", "5.0.0"))
    finding = await a.analyze(Package(name="pyjwt", version="1.0"), NOW)
    assert finding.package.version == "1.0" and not finding.package.version_assumed


@pytest.mark.asyncio
async def test_no_assume_latest_leaves_it_unpinned():
    a = analyzer(releases("4.2.0"), assume=False)
    finding = await a.analyze(Package(name="pyjwt", version=None), NOW)
    assert finding.package.version is None


@pytest.mark.asyncio
async def test_a_range_nothing_satisfies_is_a_gap():
    a = analyzer(releases("1.0"))
    finding = await a.analyze(Package(name="pyjwt", version=None, specifier=">=9"), NOW)
    assert finding.package.version is None
    assert any("no PyPI release satisfies the declared range >=9" in g
               for g in finding.remediation.gaps)


# --- the label never goes missing ------------------------------------------

def assumed(name="demo", verdict=Verdict.MITIGATE, affecting=0) -> Finding:
    pkg = Package(name=name, version="2.0", version_assumed=True)
    adv = AdvisoryHistory(total=affecting, affecting_current=affecting,
                          ids_affecting_current=[f"GHSA-{i}" for i in range(affecting)])
    return assess(pkg, Exposure(categories=["crypto"], confidence=Confidence.CURATED),
                  Remediation(last_release=NOW, repo_archived=False, advisories=adv), now=NOW)


def test_the_evidence_says_the_version_was_assumed():
    f = assumed(affecting=1)
    claims = [r.claim for r in f.reasons]
    assert any("newest release 2.0 (assumed: nothing pins this package) is affected" in c
               for c in claims)
    assert not any("pinned version" in c for c in claims)


def test_the_table_marks_it_and_the_header_explains(capsys):
    render(Console(width=100, force_terminal=False),
           [assumed(affecting=1), assumed("pinned", affecting=1)],
           sources=["r.txt"], now=NOW)
    out = capsys.readouterr().out
    assert "2.0?" in out
    assert "advisories matched against the newest release instead, marked ?" in out
    assert "advisory matching skipped" not in out


def test_skipped_and_assumed_are_reported_separately(capsys):
    unpinned = Finding(package=Package(name="u", version=None),
                       exposure=Exposure(categories=["crypto"], confidence=Confidence.CURATED),
                       remediation=Remediation(), verdict=Verdict.MITIGATE)
    render(Console(width=100, force_terminal=False), [assumed(), unpinned],
           sources=["r.txt"], now=NOW)
    out = capsys.readouterr().out
    assert "1 of 2 without a pinned version: advisories matched" in out
    assert "1 of 2 without a pinned version: advisory matching skipped" in out


def test_explain_says_it_plainly(capsys):
    render_explain(Console(width=100, force_terminal=False), assumed())
    out = capsys.readouterr().out
    assert "2.0 (assumed)" in out and "Nothing pins this package" in out


def test_markdown_and_json_carry_the_flag():
    f = assumed(affecting=1)
    assert "2.0?" in render_markdown([f], sources=["r.txt"], now=NOW)
    payload = to_dict([f], [], NOW)
    row = payload["findings"][0]
    assert row["version"] == "2.0" and row["version_assumed"] is True
    assert payload["assumed"] == 1 and payload["unpinned"] == 0
