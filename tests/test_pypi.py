"""PyPI metadata handling. Pure functions that everything downstream trusts."""

from __future__ import annotations

import datetime as dt

from package_doctor.sources.pypi import (
    PyPISource,
    extract_github_repo,
    normalise,
    parse_ts,
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
