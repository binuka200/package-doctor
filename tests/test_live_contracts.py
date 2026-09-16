"""Live contract tests: do the real APIs still return the shapes we parse?

Every other test in this suite stubs the network, which proves the code is
self-consistent but nothing about upstream. These run against the real PyPI,
OSV, ecosyste.ms, CISA and FIRST endpoints and exist to catch *drift* - a
renamed field, a changed envelope, a new pagination cap.

They are excluded from the default run (`-m "not live"` in pyproject) and run
on a schedule instead, because a dependency on four third-party services has no
business deciding whether someone's pull request is red.

The distinction they draw:

* **Service unreachable or erroring** -> skip. Somebody else's outage is not a
  defect in this tool, and paging on it trains people to ignore the suite.
* **Service responds but the shape changed** -> fail. That is drift, it will
  silently corrupt findings, and it is exactly what these tests are for.

Assertions are on structure and invariants, never on values: advisory counts
and EPSS scores move daily, and a test that pins them is a test that cries wolf.
"""

from __future__ import annotations

import contextlib
import datetime as dt

import httpx
import pytest

from package_doctor.analysis import Analyzer
from package_doctor.cache import Cache
from package_doctor.exposure import load_exposure_map
from package_doctor.models import Package, Verdict
from package_doctor.sources.client import Client
from package_doctor.sources.ecosystems import EcosystemsSource
from package_doctor.sources.exploitability import EPSS_BATCH, ExploitabilitySource
from package_doctor.sources.osv import OSVSource, build_history
from package_doctor.sources.pypi import PyPISource, extract_github_repo

pytestmark = pytest.mark.live

NOW = dt.datetime.now(dt.timezone.utc)

#: Long-lived, widely-depended-on, and certain to keep having advisories.
#: Chosen so the test does not start failing because a fixture package moved.
STABLE_PACKAGE = "django"


@pytest.fixture
def live_client():
    """A real network client with caching off, so drift cannot be masked."""
    cache = Cache(enabled=False)
    client = Client(cache, concurrency=4, timeout=30.0)
    yield client
    cache.close()


@contextlib.contextmanager
def upstream(name: str):
    """Skip on an outage; let everything else fail.

    The distinction is the entire point of these tests, so it lives in one
    place: a transport error means the service is down, and anything else -
    a KeyError, a TypeError, an assertion - means our parsing is wrong and
    must be reported as a failure rather than quietly skipped.
    """
    try:
        yield
    except (httpx.HTTPError, OSError) as exc:
        pytest.skip(f"{name} unreachable: {exc!r}")


# --- PyPI -------------------------------------------------------------------

async def test_pypi_still_exposes_the_fields_we_read(live_client):
    source = PyPISource(live_client)
    with upstream("PyPI"):
        data = await source.fetch(STABLE_PACKAGE)
    if data is None:
        pytest.skip("PyPI returned nothing; treating as an outage")

    assert "info" in data and "releases" in data, "PyPI envelope changed"
    info = data["info"]
    for field in ("classifiers", "project_urls", "version", "requires_python"):
        assert field in info, f"PyPI info.{field} is gone"

    releases = source.release_dates(data)
    assert releases, "no release could be dated - upload_time_iso_8601 may have changed"
    assert all(isinstance(v, dt.datetime) for v in releases.values())

    version, released = source.last_release(data)
    assert version and released, "could not identify a latest release"
    assert released <= NOW + dt.timedelta(days=1), "release date is in the future"


async def test_repository_url_is_still_discoverable_from_pypi(live_client):
    """Repository discovery drives every maintenance signal. If PyPI reshapes
    project_urls, the tool silently loses its second axis."""
    with upstream("PyPI"):
        data = await PyPISource(live_client).fetch(STABLE_PACKAGE)
    if data is None:
        pytest.skip("PyPI returned nothing")
    slug = extract_github_repo(data["info"])
    assert slug and slug.count("/") == 1, f"could not extract a repo slug, got {slug!r}"


# --- OSV --------------------------------------------------------------------

async def test_osv_still_returns_parsable_advisories(live_client):
    with upstream("OSV"):
        vulns = await OSVSource(live_client).fetch(STABLE_PACKAGE)
    if not vulns:
        pytest.skip("OSV returned no advisories; treating as an outage")

    assert len(vulns) > 20, f"{STABLE_PACKAGE} should have many advisories, got {len(vulns)}"
    assert all("id" in v for v in vulns), "advisories lost their id field"
    assert any(v.get("published") for v in vulns), "no advisory carries a published date"
    assert any(v.get("aliases") for v in vulns), "aliases are gone - CVE mapping would break"
    assert any(
        "fixed" in event
        for v in vulns
        for a in v.get("affected", [])
        for r in a.get("ranges", [])
        for event in r.get("events", [])
    ), "no fixed-version events found - the whole timeline depends on these"


async def test_the_advisory_timeline_still_computes(live_client):
    """The headline metric. If this stops producing a timely/late split, the
    tool is reporting a maintenance signal it can no longer measure."""
    pypi, osv = PyPISource(live_client), OSVSource(live_client)
    with upstream("PyPI/OSV"):
        data = await pypi.fetch(STABLE_PACKAGE)
        vulns = await osv.fetch(STABLE_PACKAGE)
    if not data or not vulns:
        pytest.skip("upstream returned nothing")

    history = build_history(STABLE_PACKAGE, vulns, pypi.release_dates(data), None)
    assert history.total == len(vulns)
    assert history.timely + history.late > 0, "no advisory could be placed on a timeline"
    # A major, well-run project should overwhelmingly fix at or before disclosure.
    # If this inverts, our reading of the dates is wrong, not Django's practice.
    assert history.timely > history.late, (
        f"timely={history.timely} late={history.late} - date handling may have regressed"
    )
    assert history.unmatched < history.total * 0.5, "half the advisories are undatable"


# --- ecosyste.ms ------------------------------------------------------------

async def test_ecosystems_still_returns_repository_signals(live_client):
    with upstream("ecosyste.ms"):
        repo = await EcosystemsSource(live_client).fetch_repo("django/django")
    if not repo.found:
        pytest.skip("ecosyste.ms returned nothing; treating as an outage")

    assert repo.archived is False, "django/django should not be archived"
    assert repo.pushed_at is not None, "pushed_at is gone - the commit signal depends on it"
    assert repo.pushed_at <= NOW + dt.timedelta(days=1)
    assert isinstance(repo.open_issues, int)


# --- CISA KEV and FIRST EPSS ------------------------------------------------

async def test_kev_catalogue_still_parses(live_client):
    with upstream("CISA"):
        kev = await ExploitabilitySource(live_client).kev_catalogue()
    if not kev:
        pytest.skip("KEV returned empty; treating as an outage")

    assert len(kev) > 500, f"KEV catalogue looks truncated: {len(kev)} entries"
    assert all(c.startswith("CVE-") for c in list(kev)[:50])
    # Log4Shell is not leaving this list.
    assert "CVE-2021-44228" in kev, "a known KEV entry is missing - schema may have changed"


async def test_epss_scores_more_cves_than_one_batch_holds(live_client):
    """The 100-CVE cap is load-bearing: if it tightened and we kept sending
    100, scores would go missing silently rather than erroring.

    The CVE ids come from OSV rather than being generated, for two reasons: a
    made-up id in an unassigned range is legitimately absent from EPSS and would
    fail this test for no reason, and sourcing them from OSV exercises the real
    advisory -> CVE -> score join the tool performs.
    """
    osv = OSVSource(live_client)
    source = ExploitabilitySource(live_client)
    ids: set[str] = set()
    with upstream("OSV/FIRST"):
        for package in ("django", "pillow", "tensorflow"):
            for vuln in await osv.fetch(package):
                ids.update(
                    str(a) for a in vuln.get("aliases") or [] if str(a).startswith("CVE-")
                )
        scores = await source.epss_scores(sorted(ids))
    if not ids or not scores:
        pytest.skip("upstream returned nothing; treating as an outage")

    assert len(ids) > EPSS_BATCH, (
        f"only gathered {len(ids)} CVEs; cannot exercise chunking"
    )
    assert all(0.0 <= v <= 1.0 for v in scores.values()), "EPSS values out of range"
    # Anything beyond a single batch proves the chunking round-trips.
    assert len(scores) > EPSS_BATCH, (
        f"{len(scores)} of {len(ids)} scored - the batch cap may have changed"
    )
    # These are real, published CVEs; near-total coverage is the expectation.
    assert len(scores) > len(ids) * 0.9, (
        f"only {len(scores)} of {len(ids)} real CVEs scored"
    )


async def test_kev_and_epss_agree_on_a_known_exploited_cve(live_client):
    """Log4Shell is on KEV and scores near the top of EPSS. If the two sources
    ever disagree about it, one of them is being parsed wrongly."""
    source = ExploitabilitySource(live_client)
    with upstream("CISA/FIRST"):
        kev = await source.kev_catalogue()
        scores = await source.epss_scores(["CVE-2021-44228"])
    if not kev or not scores:
        pytest.skip("upstream returned nothing")

    assert "CVE-2021-44228" in kev
    assert scores["CVE-2021-44228"] > 0.5, "a famously exploited CVE should score high"


# --- the whole pipeline -----------------------------------------------------

async def test_a_real_package_produces_a_coherent_finding(live_client):
    """End to end against live data: every source, the risk model, and the
    verdict. Asserts internal consistency rather than a particular outcome."""
    analyzer = Analyzer(live_client, load_exposure_map())
    with upstream("upstream"):
        finding = await analyzer.analyze(Package(name="requests", version="2.19.0"), NOW)

    assert finding.error is None, finding.error
    assert finding.exposure.is_exposed, "requests should be at a trust boundary"
    assert finding.remediation.last_release is not None
    assert finding.remediation.repo_url

    adv = finding.remediation.advisories
    assert adv.total > 5
    assert adv.affecting_current > 0, "requests 2.19.0 is old and should be affected"
    assert adv.cves_affecting_current, "no CVE aliases resolved for an affected version"

    # An old, exposed, affected version must be actionable: at the least an
    # upgrade, since requests is maintained and has shipped the fixes.
    assert finding.verdict in (Verdict.EXPLOITED, Verdict.REPLACE, Verdict.UPGRADE)
    assert finding.reasons, "an actionable verdict with no stated reason is unusable"
    assert all(r.claim for r in finding.reasons)


async def test_a_healthy_package_is_not_flagged(live_client):
    """The other half of the contract: staying quiet. `six` is dormant by
    design and must never reach the actionable list."""
    analyzer = Analyzer(live_client, load_exposure_map())
    with upstream("upstream"):
        finding = await analyzer.analyze(Package(name="six", version="1.17.0"), NOW)

    assert finding.verdict is not Verdict.REPLACE
    assert not finding.exposure.is_exposed


# --- the harness itself -----------------------------------------------------

def test_outages_skip_but_real_errors_fail():
    """These tests are only trustworthy if that distinction actually holds."""
    with pytest.raises(pytest.skip.Exception), upstream("x"):
        raise httpx.ConnectError("down")

    with pytest.raises(KeyError), upstream("x"):
        raise KeyError("a field we parse has been renamed")

    with pytest.raises(AssertionError), upstream("x"):
        raise AssertionError("a contract assertion must not be swallowed")
