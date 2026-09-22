"""Findings from a second outside review, each pinned to its fix.

A --src file outside the project rendered as ".:7"; a `name @ url` line
was classified by its suffix as a local path named by the whole line; a
wheel filename was normalised into nonsense; the maintenance date was
GitHub's any-branch push time, fourteen months newer than the default
branch for flask-restful; a renamed repository read as "metadata
unavailable"; and that gap showed only in explain, never in the table.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from package_doctor.models import (
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.parsers.discovery import (
    DependencySet,
    _distribution_name,
    _unresolvable_line,
    parse_requirements_txt,
)
from package_doctor.report import SECTIONS, render, render_explain, render_markdown, to_dict
from package_doctor.risk import assess
from package_doctor.sources.ecosystems import EcosystemsSource, RepoInfo
from package_doctor.sourcescan import _relative, build_index

NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)


# --- --src outside the project ---------------------------------------------

def test_a_single_file_outside_the_project_keeps_its_name(tmp_path, monkeypatch):
    project = tmp_path / "configs"
    project.mkdir()
    app = tmp_path / "app.py"
    app.write_text("import flask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    index = build_index(app, known_packages={"flask"}, display_root=project)
    assert [str(s) for s in index.for_package("flask")] == ["app.py:1"]


def test_relative_never_answers_dot_for_a_file():
    path = Path("/somewhere/app.py")
    assert _relative(path, Path("/elsewhere"), path) != "."
    assert _relative(path, Path("/somewhere")) == "app.py"


# --- name @ url, and archive filenames -------------------------------------

def test_a_direct_reference_is_a_url_named_by_its_name(tmp_path):
    deps = DependencySet()
    parse_requirements_txt(tmp_path / "requirements.txt", deps,
                           "requests @ https://example.com/requests-2.0.tar.gz\n")
    assert deps.versions == {}
    assert deps.not_analysed == {"requests": "url"}
    assert _unresolvable_line("requests @ https://example.com/requests-2.0.tar.gz") is None


@pytest.mark.parametrize("filename, expected", [
    ("foo-1.0-py3-none-any.whl", "foo"),
    ("Foo_Bar-2.3.1-cp312-cp312-manylinux_2_17_x86_64.whl", "Foo_Bar"),
    ("bar-2.3.1.tar.gz", "bar"),
    ("my-lib-0.1.0rc1.tar.gz", "my-lib"),
    ("thing-1.0.zip", "thing"),
    ("thing.tgz", "thing"),
    ("notanarchive", None),
    ("README.md", None),
])
def test_archive_filenames_yield_the_distribution_name(filename, expected):
    assert _distribution_name(filename) == expected


def test_bare_archive_urls_and_paths_are_named_by_distribution(tmp_path):
    deps = DependencySet()
    parse_requirements_txt(tmp_path / "requirements.txt", deps,
                           "https://example.com/foo-1.0-py3-none-any.whl\n"
                           "./dist/bar-2.3.1.tar.gz\n"
                           "./vendor/baz\n")
    assert deps.not_analysed == {"foo": "url", "bar": "path", "./vendor/baz": "path"}


# --- the maintenance date --------------------------------------------------

FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Recent Commits</title>
<updated>2023-05-21T03:47:13Z</updated>
<entry><id>1</id><updated>2023-05-21T03:47:13Z</updated><title>fix</title></entry>
<entry><id>2</id><updated>2023-05-21T03:45:32Z</updated><title>older</title></entry>
</feed>"""

REPO = {"archived": False, "pushed_at": "2024-07-19T22:46:03.000Z", "default_branch": "master",
        "open_issues_count": 3, "html_url": "https://github.com/x/y"}


def transport(routes: dict[str, httpx.Response]):
    def handler(request: httpx.Request) -> httpx.Response:
        for prefix, response in routes.items():
            if str(request.url).startswith(prefix):
                return response
        return httpx.Response(404)
    return handler


@pytest.mark.asyncio
async def test_last_commit_comes_from_the_default_branch_feed(make_client):
    client = make_client(transport({
        "https://github.com/x/y/commits/master.atom": httpx.Response(200, text=FEED),
    }))
    async with client:
        stamp = await EcosystemsSource(client).last_commit("x/y", "master")
    assert stamp == dt.datetime(2023, 5, 21, 3, 47, 13, tzinfo=dt.timezone.utc)


@pytest.mark.asyncio
async def test_the_feed_is_cached_as_one_timestamp_not_the_body(make_client, cache):
    client = make_client(transport({
        "https://github.com/x/y/commits/master.atom": httpx.Response(200, text=FEED),
    }))
    async with client:
        await EcosystemsSource(client).last_commit("x/y", "master")
    entry = cache.get("github:feed:x/y:master")
    assert entry["body"] == "2023-05-21T03:47:13Z"


@pytest.mark.asyncio
async def test_a_missing_or_malformed_feed_is_none(make_client):
    client = make_client(transport({
        "https://github.com/x/y/commits/main.atom": httpx.Response(200, text="<html>nope</html>"),
    }))
    async with client:
        src = EcosystemsSource(client)
        assert await src.last_commit("x/y", "main") is None
        assert await src.last_commit("x/y", "gone") is None


@pytest.mark.asyncio
async def test_fetch_repo_records_the_default_branch(make_client):
    client = make_client(transport({
        "https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/x%2Fy":
            httpx.Response(200, json=REPO),
    }))
    async with client:
        repo = await EcosystemsSource(client).fetch_repo("x/y")
    assert repo.found and repo.default_branch == "master" and repo.slug == "x/y"


def test_the_staleness_signal_prefers_the_default_branch_date():
    rem = Remediation(
        last_release=NOW - dt.timedelta(days=100),
        repo_archived=False,
        repo_last_push=NOW - dt.timedelta(days=100),          # a bot branch, last week
        repo_last_commit=NOW - dt.timedelta(days=800),        # the code, two years ago
    )
    assert rem.days_since_push(NOW) == 800
    finding = assess(Package(name="p", version="1"), Exposure(categories=["crypto"],
                     confidence=Confidence.CURATED), rem, now=NOW)
    assert any("no commits in" in r.claim for r in finding.abandonment_signals)


def test_without_the_feed_the_push_date_still_serves():
    rem = Remediation(repo_last_push=NOW - dt.timedelta(days=30))
    assert rem.days_since_push(NOW) == 30


def _analyzer(repo: RepoInfo, feed_calls: list, moved: str | None = None):
    from package_doctor.analysis import Analyzer
    from package_doctor.exposure import load_exposure_map
    from package_doctor.models import Exploitability
    from package_doctor.risk import Thresholds

    a = Analyzer.__new__(Analyzer)
    a.exposure_map = load_exposure_map()
    a.thresholds = Thresholds()
    a.skip_repo = False
    a.assume_latest = False

    class P:
        async def fetch(self, name):
            return {"info": {"project_urls": {"Source": "https://github.com/old/name"}},
                    "releases": {"1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}}
        release_dates = staticmethod(lambda d: {"1.0": NOW - dt.timedelta(days=100)})
        last_release = staticmethod(lambda d: ("1.0", NOW - dt.timedelta(days=100)))
        last_upload = staticmethod(lambda d: ("1.0", NOW - dt.timedelta(days=100)))
        has_inactive_classifier = staticmethod(lambda d: False)

    class Osv:
        async def fetch(self, name):
            return []

    class R:
        async def fetch_repo(self, slug):
            if moved and slug == moved:
                return repo
            if moved:
                return RepoInfo(found=False, url=f"https://github.com/{slug}")
            return repo

        async def last_commit(self, slug, branch):
            feed_calls.append((slug, branch))
            return NOW - dt.timedelta(days=700)

        async def resolve_rename(self, slug):
            return moved

    class E:
        async def assess(self, cves):
            return Exploitability()

        async def kev_catalogue(self):
            return frozenset()

    a.pypi, a.osv, a.repos, a.exploit = P(), Osv(), R(), E()
    return a


@pytest.mark.asyncio
async def test_the_feed_is_fetched_only_when_the_push_date_looks_alive():
    calls: list = []
    alive = RepoInfo(True, False, NOW - dt.timedelta(days=10), 0, "u", "x/y", "main")
    finding = await _analyzer(alive, calls).analyze(Package(name="p", version="1.0"), NOW)
    assert calls == [("x/y", "main")]
    assert finding.remediation.repo_last_commit == NOW - dt.timedelta(days=700)
    assert finding.remediation.days_since_push(NOW) == 700

    calls.clear()
    stale = RepoInfo(True, False, NOW - dt.timedelta(days=900), 0, "u", "x/y", "main")
    finding = await _analyzer(stale, calls).analyze(Package(name="p", version="1.0"), NOW)
    assert calls == [], "already past the threshold; the feed cannot make it fresher"
    assert finding.remediation.repo_last_commit is None


@pytest.mark.asyncio
async def test_a_renamed_repository_is_followed():
    calls: list = []
    at_new = RepoInfo(True, False, NOW - dt.timedelta(days=10), 0,
                      "https://github.com/new/name", "new/name", "main")
    finding = await _analyzer(at_new, calls, moved="new/name").analyze(
        Package(name="p", version="1.0"), NOW
    )
    assert finding.remediation.repo_url == "https://github.com/new/name"
    assert finding.remediation.repo_archived is False
    assert "repository metadata unavailable" not in finding.remediation.gaps
    assert calls == [("new/name", "main")]


@pytest.mark.asyncio
async def test_redirect_target_reads_location_without_following(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "HEAD" and str(request.url) == "https://github.com/old/name":
            return httpx.Response(301, headers={"location": "https://github.com/new/name"})
        return httpx.Response(200)
    client = make_client(handler)
    async with client:
        src = EcosystemsSource(client)
        assert await src.resolve_rename("old/name") == "new/name"
        assert await src.resolve_rename("new/name") is None, "no redirect: not renamed"


# --- the gap reaches the table ---------------------------------------------

def _finding(gaps: list[str], verdict=Verdict.QUIET) -> Finding:
    return Finding(
        package=Package(name="gearman3", version="1.0"),
        exposure=Exposure(categories=[], confidence=Confidence.CURATED),
        remediation=Remediation(last_release=NOW - dt.timedelta(days=2000), gaps=gaps),
        verdict=verdict,
        reasons=[Evidence("no release in 5.3y")],
    )


def test_a_failed_lookup_is_named_in_the_table_and_markdown(capsys):
    f = _finding(["repository metadata unavailable"])
    render(Console(width=120, force_terminal=False), [f], sources=["r.txt"], now=NOW,
           show_all=True)
    assert "missing signal: repository metadata unavailable" in capsys.readouterr().out
    assert "missing signal: repository metadata unavailable" in render_markdown(
        [f], sources=["r.txt"], now=NOW
    )


def test_a_fact_about_the_package_is_not_called_a_missing_signal(capsys):
    f = _finding(["no source repository declared on PyPI"])
    render(Console(width=120, force_terminal=False), [f], sources=["r.txt"], now=NOW,
           show_all=True)
    assert "missing signal" not in capsys.readouterr().out


def test_explain_distinguishes_the_two_dates(capsys):
    f = _finding([])
    f.remediation.repo_last_push = NOW - dt.timedelta(days=100)
    f.remediation.repo_last_commit = NOW - dt.timedelta(days=800)
    render_explain(Console(width=120, force_terminal=False), f)
    out = capsys.readouterr().out
    assert "(default branch)" in out and "(any branch or tag)" in out
    payload = to_dict([f], [], NOW)
    assert payload["findings"][0]["remediation"]["repo_last_commit"].startswith("2024-")


# --- a maintained package at a trust boundary -------------------------------

def test_a_maintained_boundary_package_is_an_inventory_not_a_finding(capsys):
    """It is where the next advisory that matters will land, but there is
    nothing to do about it today, so it is not a section of the report."""
    hint = next(h for v, _, h, _ in SECTIONS if v is Verdict.QUIET)
    assert "nothing wrong today" in hint
    f = assess(
        Package(name="requests", version="2.0"),
        Exposure(categories=["http/network"], confidence=Confidence.CURATED),
        Remediation(last_release=NOW, repo_archived=False, repo_last_commit=NOW,
                    advisories=__import__("package_doctor.models", fromlist=["AdvisoryHistory"])
                    .AdvisoryHistory(total=5, timely=5)),
        now=NOW,
    )
    assert f.verdict is Verdict.OK
    render(Console(width=120, force_terminal=False), [f], sources=["r.txt"], now=NOW)
    assert "requests" not in capsys.readouterr().out
    render(Console(width=120, force_terminal=False), [f], sources=["r.txt"], now=NOW,
           show_ok=True)
    assert "requests" in capsys.readouterr().out
