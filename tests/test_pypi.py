"""PyPI metadata handling. Pure functions that everything downstream trusts."""

from __future__ import annotations

import datetime as dt

from package_doctor.sources.pypi import (
    PyPISource,
    extract_github_repo,
    normalise,
    parse_ts,
    reduce_pypi,
)


def files(*stamps, yanked=False):
    return [
        {"upload_time_iso_8601": s, "yanked": yanked} for s in stamps
    ]


# --- normalisation ----------------------------------------------------------

def test_pep503_normalisation():
    assert normalise("Flask_Login") == "flask-login"
    assert normalise("zope.interface") == "zope-interface"
    assert normalise("ruamel.yaml") == "ruamel-yaml"
    assert normalise("A__B..C") == "a-b-c"


def test_parse_ts_handles_zulu_and_bad_input():
    assert parse_ts("2024-01-01T00:00:00Z").year == 2024
    assert parse_ts(None) is None
    assert parse_ts("not a date") is None


# --- release timeline -------------------------------------------------------

def test_release_dates_uses_the_earliest_file_in_a_release():
    """Wheels for extra platforms can trail the original upload by weeks, and
    using the latest would distort every advisory timeline."""
    data = {"releases": {"1.0": files("2024-03-01T00:00:00Z", "2024-01-01T00:00:00Z")}}
    assert PyPISource.release_dates(data)["1.0"] == dt.datetime(
        2024, 1, 1, tzinfo=dt.timezone.utc
    )


def test_release_dates_skips_releases_with_no_files():
    data = {"releases": {"1.0": [], "2.0": files("2024-01-01T00:00:00Z")}}
    assert set(PyPISource.release_dates(data)) == {"2.0"}


def test_last_release_picks_the_newest():
    data = {"releases": {
        "1.0": files("2020-01-01T00:00:00Z"),
        "2.0": files("2024-01-01T00:00:00Z"),
        "1.5": files("2022-01-01T00:00:00Z"),
    }}
    version, date = PyPISource.last_release(data)
    assert version == "2.0" and date.year == 2024


def test_last_release_ignores_a_fully_yanked_release():
    """A yanked release is not what a user installs, so treating it as the
    project's latest activity would overstate how alive the project is."""
    data = {"releases": {
        "1.0": files("2020-01-01T00:00:00Z"),
        "2.0": files("2024-01-01T00:00:00Z", yanked=True),
    }}
    version, _ = PyPISource.last_release(data)
    assert version == "1.0"


def test_last_release_keeps_a_partially_yanked_release():
    data = {"releases": {"2.0": [
        {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": True},
        {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": False},
    ]}}
    assert PyPISource.last_release(data)[0] == "2.0"


def test_last_release_on_an_empty_project():
    assert PyPISource.last_release({"releases": {}}) == (None, None)


def test_last_upload_sees_a_trailing_wheel_that_last_release_misses():
    """A new-Python wheel added to an old version post-dates the newest
    version: last_release reports the version date, last_upload the activity."""
    data = {"releases": {
        # 1.0 got a fresh wheel in 2025, long after 2.0 was the last version.
        "1.0": [
            {"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": False},
            {"latest_upload_time_iso_8601": "2025-06-01T00:00:00Z",
             "upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": False},
        ],
        "2.0": files("2024-01-01T00:00:00Z"),
    }}
    assert PyPISource.last_release(data)[0] == "2.0"
    version, date = PyPISource.last_upload(data)
    assert version == "1.0" and date.year == 2025


def test_last_upload_falls_back_to_earliest_field_for_old_cache_entries():
    """Pre-v3 cache entries have no latest field; the earliest one is used."""
    data = {"releases": {
        "1.0": files("2020-01-01T00:00:00Z"),
        "2.0": files("2024-01-01T00:00:00Z"),
    }}
    version, date = PyPISource.last_upload(data)
    assert version == "2.0" and date.year == 2024


def test_last_upload_counts_a_yanked_release_as_activity():
    """Unlike last_release, a yank is itself a maintainer touching the package."""
    data = {"releases": {
        "1.0": files("2020-01-01T00:00:00Z"),
        "2.0": files("2024-01-01T00:00:00Z", yanked=True),
    }}
    assert PyPISource.last_upload(data)[0] == "2.0"


def test_last_upload_on_an_empty_project():
    assert PyPISource.last_upload({"releases": {}}) == (None, None)


# --- classifiers ------------------------------------------------------------

def test_inactive_classifier_detection():
    yes = {"info": {"classifiers": ["Development Status :: 7 - Inactive"]}}
    no = {"info": {"classifiers": ["Development Status :: 5 - Production/Stable"]}}
    assert PyPISource.has_inactive_classifier(yes)
    assert not PyPISource.has_inactive_classifier(no)
    assert not PyPISource.has_inactive_classifier({"info": {}})


# --- repository discovery ---------------------------------------------------

def test_prefers_an_explicit_source_url_over_a_homepage():
    info = {"project_urls": {
        "Homepage": "https://github.com/docs/website",
        "Source": "https://github.com/real/project",
    }}
    assert extract_github_repo(info) == "real/project"


def test_strips_a_git_suffix():
    info = {"project_urls": {"Source": "https://github.com/a/b.git"}}
    assert extract_github_repo(info) == "a/b"


def test_ignores_sponsor_links():
    """github.com/sponsors/<user> is a funding page, not a repository."""
    info = {"project_urls": {
        "Funding": "https://github.com/sponsors/someone",
        "Source": "https://github.com/real/project",
    }}
    assert extract_github_repo(info) == "real/project"


def test_falls_back_to_home_page():
    assert extract_github_repo({"home_page": "https://github.com/a/b"}) == "a/b"


def test_returns_none_when_there_is_no_github_link():
    """Fewer than two thirds of PyPI projects declare a repository, so this is
    the common case and must produce a gap rather than a guess."""
    assert extract_github_repo({"project_urls": {"Docs": "https://readthedocs.org/x"}}) is None
    assert extract_github_repo({}) is None


def test_tolerates_non_string_project_urls():
    assert extract_github_repo({"project_urls": None, "home_page": None}) is None


# --- the cached body is a fraction of the response ---------------------------

def full_body():
    """A response shaped like PyPI's, with the bulk the tool never reads."""
    def file(stamp, yanked=False, kind="bdist_wheel"):
        return {
            "upload_time_iso_8601": stamp, "yanked": yanked, "packagetype": kind,
            "filename": "x.whl", "url": "https://files.pythonhosted.org/x.whl",
            "digests": {"sha256": "0" * 64, "md5": "0" * 32}, "size": 12345,
            "downloads": -1, "comment_text": "", "has_sig": False,
        }
    return {
        "info": {
            "name": "demo", "version": "2.0", "summary": "a demo",
            "description": "x" * 50_000, "description_content_type": "text/markdown",
            "author": "someone", "author_email": "a@b.c", "license": "MIT",
            "classifiers": ["Development Status :: 7 - Inactive"],
            "project_urls": {"Source": "https://github.com/o/demo"},
            "home_page": "", "download_url": "", "keywords": "k", "requires_python": ">=3.9",
        },
        "releases": {
            "1.0": [file("2020-03-01T00:00:00Z"), file("2020-01-01T00:00:00Z", kind="sdist")],
            "1.5": [
                file("2022-01-01T00:00:00Z", yanked=True),
                file("2022-01-02T00:00:00Z", yanked=True),
            ],
            "1.6": [file("2022-06-01T00:00:00Z", yanked=True), file("2022-06-01T00:00:00Z")],
            "2.0": [file("2024-01-01T00:00:00Z")],
            "3.0": [],
        },
        "urls": [file("2024-01-01T00:00:00Z")],
        "vulnerabilities": [],
        "last_serial": 123,
    }


def test_reduced_body_gives_identical_answers():
    """Every reader must see the same thing through the reduced shape."""
    full, slim = full_body(), reduce_pypi(full_body())
    assert PyPISource.release_dates(slim) == PyPISource.release_dates(full)
    assert PyPISource.last_release(slim) == PyPISource.last_release(full)
    assert PyPISource.last_upload(slim) == PyPISource.last_upload(full)
    assert PyPISource.has_inactive_classifier(slim) == PyPISource.has_inactive_classifier(full)
    assert extract_github_repo(slim["info"]) == extract_github_repo(full["info"])
    assert PyPISource.last_release(slim)[0] == "2.0"
    assert set(PyPISource.release_dates(slim)) == {"1.0", "1.5", "1.6", "2.0"}


def test_reduced_body_is_small():
    import json
    full, slim = full_body(), reduce_pypi(full_body())
    assert len(json.dumps(slim)) * 20 < len(json.dumps(full))
    assert "description" not in slim["info"]
    assert "urls" not in slim and "last_serial" not in slim
    for files in slim["releases"].values():
        assert len(files) <= 1
        for f in files:
            assert set(f) == {
                "upload_time_iso_8601",
                "latest_upload_time_iso_8601",
                "yanked",
            }


def test_reduction_keeps_the_earliest_file_by_time_not_by_string():
    slim = reduce_pypi({"releases": {"1.0": [
        {"upload_time_iso_8601": "2024-01-01T00:00:00+00:00"},
        {"upload_time_iso_8601": "2023-12-31T23:00:00Z"},
    ]}})
    assert slim["releases"]["1.0"][0]["upload_time_iso_8601"] == "2023-12-31T23:00:00Z"


def test_reduction_keeps_the_latest_file_by_time_not_by_string():
    slim = reduce_pypi({"releases": {"1.0": [
        {"upload_time_iso_8601": "2024-01-01T00:00:00+00:00"},
        {"upload_time_iso_8601": "2024-02-01T09:00:00Z"},
    ]}})
    f = slim["releases"]["1.0"][0]
    assert f["upload_time_iso_8601"] == "2024-01-01T00:00:00+00:00"
    assert f["latest_upload_time_iso_8601"] == "2024-02-01T09:00:00Z"


def test_reduction_marks_a_release_yanked_only_when_every_file_is():
    slim = reduce_pypi(full_body())
    assert slim["releases"]["1.5"][0]["yanked"] is True
    assert slim["releases"]["1.6"][0]["yanked"] is False


def test_reduction_survives_malformed_shapes():
    assert reduce_pypi(None) is None
    assert reduce_pypi([]) == []
    assert reduce_pypi({}) == {"info": {}, "releases": {}}
    slim = reduce_pypi({
        "info": "not a dict",
        "releases": {"1.0": "nope", "2.0": [1, "x"], "3.0": [{}]},
    })
    assert slim["info"] == {}
    assert "1.0" not in slim["releases"]
    assert slim["releases"]["2.0"] == []
    assert slim["releases"]["3.0"] == [
        {
            "upload_time_iso_8601": None,
            "latest_upload_time_iso_8601": None,
            "yanked": False,
        }
    ]


async def test_fetch_caches_the_reduced_body_not_the_response(cache):
    """The point of reducing is that the cache holds the small shape."""
    import httpx

    from package_doctor.sources.client import Client

    c = Client(cache)
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json=full_body())
    ))
    data = await PyPISource(c).fetch("demo")
    assert data is not None and "description" not in data["info"]
    stored = cache.get("pypi:v3:demo")
    assert stored["body"] == data
    assert cache.get("pypi:demo") is None, "the old key is never written"
    await c.aclose()
