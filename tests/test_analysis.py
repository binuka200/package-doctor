"""The orchestrator: what happens when a source is unavailable."""

from __future__ import annotations

import datetime as dt

import pytest

from package_doctor.analysis import Analyzer
from package_doctor.exposure import load_exposure_map
from package_doctor.models import Package, Verdict
from package_doctor.sources.ecosystems import RepoInfo

NOW = dt.datetime(2026, 9, 12, tzinfo=dt.timezone.utc)


def build(monkeypatch, pypi=None, vulns=(), repo=None):
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.exposure_map = load_exposure_map()
    from package_doctor.risk import Thresholds
    analyzer.thresholds = Thresholds()
    analyzer.skip_repo = False

    class P:
        async def fetch(self, name): return pypi
        release_dates = staticmethod(lambda d: {})
        last_release = staticmethod(lambda d: (None, None))
        has_inactive_classifier = staticmethod(lambda d: False)

    class O:
        async def fetch(self, name): return list(vulns)

    class R:
        async def fetch_repo(self, slug): return repo or RepoInfo(found=False)

    class E:
        async def assess(self, cves): 
            from package_doctor.models import Exploitability
            return Exploitability()
        async def kev_catalogue(self): return frozenset()

    analyzer.pypi, analyzer.osv, analyzer.repos, analyzer.exploit = P(), O(), R(), E()
    return analyzer


@pytest.mark.asyncio
async def test_a_package_missing_from_pypi_is_an_error_not_a_crash(monkeypatch):
    analyzer = build(monkeypatch, pypi=None)
    finding = await analyzer.analyze(Package(name="ghost", version="1.0"), NOW)
    assert finding.error == "not found on PyPI"
    assert "not found on PyPI" in finding.remediation.gaps


@pytest.mark.asyncio
async def test_a_package_with_no_declared_repository_records_a_gap(monkeypatch):
    analyzer = build(monkeypatch, pypi={"info": {"project_urls": {}}, "releases": {}})
    finding = await analyzer.analyze(Package(name="pyjwt", version="1.0"), NOW)
    assert any("no source repository" in g for g in finding.remediation.gaps)


@pytest.mark.asyncio
async def test_unreachable_repository_metadata_is_a_gap_not_a_zero(monkeypatch):
    """An API being down must never read as 'this project is dead'."""
    analyzer = build(
        monkeypatch,
        pypi={"info": {"project_urls": {"Source": "https://github.com/a/b"}}, "releases": {}},
        repo=RepoInfo(found=False, url="https://github.com/a/b"),
    )
    finding = await analyzer.analyze(Package(name="pyjwt", version="1.0"), NOW)
    assert any("repository metadata unavailable" in g for g in finding.remediation.gaps)
    assert finding.remediation.repo_archived is None
    assert finding.verdict is not Verdict.ACT


@pytest.mark.asyncio
async def test_one_failing_package_does_not_abort_the_scan(monkeypatch):
    analyzer = build(monkeypatch, pypi={"info": {}, "releases": {}})

    async def boom(package, now):
        raise RuntimeError("upstream exploded")

    analyzer.analyze = boom
    findings = await analyzer.analyze_all(
        [Package(name="a", version="1.0"), Package(name="b", version="1.0")], NOW
    )
    assert len(findings) == 2
    assert all(f.error for f in findings)
    assert all(f.verdict is Verdict.UNKNOWN for f in findings)
