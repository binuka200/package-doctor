"""Five ways a dependency used to fall through without a word.

Each was found on a real project. A wildcard pin was analysed as the newest
release of all; setuptools was dropped from the count; git-sourced
first-party packages vanished; a dependency file could not be named
directly; and --src refused a file its own help text allowed. The tests
record the exact behaviour that replaced each.
"""

from __future__ import annotations

import json
from pathlib import Path

from package_doctor import cli
from package_doctor.models import Confidence, Exposure, Finding, Remediation, Verdict
from package_doctor.parsers import collect_dependencies, discover_manifests
from package_doctor.parsers.discovery import (
    _unresolvable_line,
    is_dependency_file,
    parse_requirements_txt,
    source_kind,
)
from package_doctor.report import describe_not_analysed, to_dict
from package_doctor.sources.pypi import PyPISource


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- 1. wildcard pins are ranges -------------------------------------------

def test_a_wildcard_pin_is_kept_as_a_range(tmp_path):
    write(tmp_path, "requirements.txt", "certifi==2024.6.*\nplatformdirs===4.3.*\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"certifi": None, "platformdirs": None}
    assert deps.specifiers == {"certifi": "==2024.6.*", "platformdirs": "===4.3.*"}


def test_the_range_selects_the_newest_matching_release_not_the_newest_of_all():
    """certifi==2024.6.* was analysed as 2026.7.22, and CVE-2024-39689 went
    with it. The newest 2024.6 release is the honest answer."""
    data = {"info": {}, "releases": {
        v: [{"upload_time_iso_8601": "2026-01-01T00:00:00Z", "yanked": False}]
        for v in ("2024.6.1", "2024.6.2", "2024.7.4", "2026.7.22")
    }}
    assert PyPISource.newest_matching(data, "==2024.6.*") == "2024.6.2"


def test_wildcards_in_pyproject_poetry_pipfile_and_pipfile_lock_are_ranges(tmp_path):
    write(tmp_path, "pyproject.toml", """
[project]
dependencies = ["httpcore==1.*"]
[tool.poetry.dependencies]
pygments = "=2.*"
""")
    write(tmp_path, "Pipfile", '[packages]\nsocksio = "==1.*"\nrich = ">=13"\nsix = "*"\n')
    write(tmp_path, "Pipfile.lock", '{"default": {"anyio": {"version": "==4.*"}}}')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions["httpcore"] is None and deps.versions["anyio"] is None
    assert deps.specifiers["httpcore"] == "==1.*"
    assert deps.specifiers["pygments"] == "==2.*"
    assert deps.specifiers["socksio"] == "==1.*"
    assert deps.specifiers["rich"] == ">=13"
    assert "six" not in deps.specifiers, "a bare * is no constraint at all"
    assert deps.specifiers["anyio"] == "==4.*"


# --- 2. the packaging toolchain is analysed --------------------------------

def test_setuptools_pip_and_wheel_are_counted(tmp_path):
    write(tmp_path, "requirements.txt", "setuptools==83.0.*\nflask==3.1.3\npip==25.0\nwheel\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"setuptools", "flask", "pip", "wheel"}
    assert deps.specifiers["setuptools"] == "==83.0.*"


def test_the_interpreter_itself_is_still_not_a_package(tmp_path):
    write(tmp_path, "Pipfile.lock", '{"default": {"python": {"version": "==3.12"}}}')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {}


# --- 3. git, URL and path dependencies are named, not dropped --------------

def test_source_kinds():
    assert source_kind("git+ssh://git@github.com/o/r.git") == "git"
    assert source_kind("hg+https://x/y") == "git"
    assert source_kind("https://x/y.tar.gz") == "url"
    assert source_kind("file:///tmp/x") == "url"
    assert source_kind("./libs/thing") == "path"
    assert source_kind("/abs/path") == "path"
    assert source_kind("dist/thing-1.0-py3-none-any.whl") == "path"
    assert source_kind("requests") is None
    assert source_kind("requests==2.0") is None


def test_requirements_lines_that_name_no_index_package_are_classified():
    assert _unresolvable_line(
        "git+ssh://git@github.com/org/python-libraries/authlib-internal.git#egg=authlib-internal"
    ) == ("authlib-internal", "git")
    assert _unresolvable_line("-e git+https://github.com/org/other.git") == ("other", "git")
    assert _unresolvable_line("--editable=./libs/local") == ("./libs/local", "path")
    assert _unresolvable_line("-e .") == (".", "path")
    assert _unresolvable_line("https://files/x/thing-1.0.tar.gz  # pinned") == ("thing", "url")
    assert _unresolvable_line("requests==2.0") is None
    assert _unresolvable_line("-r base.txt") is None
    assert _unresolvable_line("# just a comment") is None


def test_first_party_git_dependencies_are_recorded_from_every_file(tmp_path):
    write(tmp_path, "requirements.txt",
          "flask==3.1.3\ngit+ssh://git@github.com/org/python-libraries/auth-internal.git\n"
          "-e git+ssh://git@github.com/org/python-libraries/other.git#egg=other\n")
    write(tmp_path, "pyproject.toml",
          '[project]\nname = "app"\n'
          'dependencies = ["third @ git+ssh://git@github.com/org/third.git", '
          '"fourth @ https://x/fourth.whl"]\n'
          '[tool.poetry.dependencies]\nfifth = { git = "https://github.com/org/fifth.git" }\n'
          'sixth = { path = "../sixth" }\n')
    write(tmp_path, "uv.lock",
          '[[package]]\nname = "seventh"\nversion = "0.1"\nsource = { git = "https://g/s.git" }\n')
    write(tmp_path, "Pipfile", '[packages]\neighth = { git = "https://g/e.git" }\n')
    write(tmp_path, "Pipfile.lock",
          '{"default": {"ninth": {"git": "https://g/n.git", "ref": "abc"}}}')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"flask": "3.1.3"}
    assert deps.not_analysed == {
        "auth-internal": "git", "other": "git", "third": "git", "fourth": "url",
        "fifth": "git", "sixth": "path", "seventh": "git", "eighth": "git", "ninth": "git",
    }


def test_a_git_dependency_is_not_looked_up_as_if_it_were_on_pypi(tmp_path):
    """The old behaviour for a PEP 508 direct reference was a PyPI lookup and
    an 'unknown: not found on PyPI' row, which implies it might be there."""
    write(tmp_path, "pyproject.toml",
          '[project]\nname = "app"\ndependencies = ["mine @ git+ssh://g/mine.git"]\n')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert "mine" not in deps.versions and deps.not_analysed == {"mine": "git"}


def test_the_report_names_them_in_every_output(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt", "flask==3.1.3\ngit+ssh://g/org/auth-internal.git\n")

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return [
                Finding(package=p, exposure=Exposure(categories=[], confidence=Confidence.CURATED),
                        remediation=Remediation(), verdict=Verdict.OK)
                for p in packages
            ]

    monkeypatch.setattr(cli, "Analyzer", Stub)
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "Not analysed: 1 dependency comes from git" in out
    assert "auth-internal (git)" in out
    assert "first-party code" in out

    md = tmp_path / "r.md"
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache", "--json",
              "--markdown", str(md)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["not_analysed"] == [{"name": "auth-internal", "source": "git"}]
    assert "auth-internal (git)" in md.read_text(encoding="utf-8")


def test_describe_not_analysed_wording():
    assert describe_not_analysed({}) is None
    text = describe_not_analysed({"a": "git", "b": "path", "c": "url"})
    assert text.startswith("Not analysed: 3 dependencies come from")
    assert "a (git), b (a local path), c (a URL)" in text


def test_json_carries_not_analysed_even_when_empty():
    import datetime as dt
    payload = to_dict([], [], dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc))
    assert payload["not_analysed"] == []


# --- 4. scan accepts a dependency file ------------------------------------

def stub_ok(monkeypatch):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return [Finding(package=p, exposure=Exposure(), remediation=Remediation(),
                            verdict=Verdict.OK) for p in packages]

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_scan_takes_a_dependency_file_as_the_project(tmp_path, monkeypatch, capsys):
    req = write(tmp_path, "configs/requirements.txt", "flask==3.1.3\n")
    stub_ok(monkeypatch)
    assert cli.main(["scan", str(req), "--no-reachability", "--no-cache"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "1 packages" in out and "from requirements.txt" in out


def test_scan_refuses_a_file_it_cannot_read_as_dependencies(tmp_path, monkeypatch, capsys):
    other = write(tmp_path, "notes.md", "flask==3.1.3\n")
    stub_ok(monkeypatch)
    assert cli.main(["scan", str(other), "--no-cache"]) == cli.EXIT_USAGE
    assert "Not a dependency file" in capsys.readouterr().out
    assert cli.main(["scan", str(tmp_path / "missing"), "--no-cache"]) == cli.EXIT_USAGE


def test_is_dependency_file():
    assert is_dependency_file(Path("/p/uv.lock"))
    assert is_dependency_file(Path("/p/requirements-dev.txt"))
    assert is_dependency_file(Path("/p/requirements/base.txt"))
    assert is_dependency_file(Path("/p/setup.cfg"))
    assert not is_dependency_file(Path("/p/setup.py"))


# --- 5. --src accepts a file ----------------------------------------------

def test_src_takes_a_single_file(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt", "flask==3.1.3\n")
    app = write(tmp_path, "app.py", "import flask\n")
    seen = {}

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            seen["sites"] = {p.name: p.import_sites for p in packages}
            return [Finding(package=p, exposure=Exposure(), remediation=Remediation(),
                            verdict=Verdict.OK) for p in packages]

    monkeypatch.setattr(cli, "Analyzer", Stub)
    assert cli.main(["scan", str(tmp_path), "--src", str(app), "--no-cache"]) == cli.EXIT_OK
    assert seen["sites"]["flask"] == ["app.py:1"]
    assert "skipping" not in capsys.readouterr().out


def test_src_that_does_not_exist_says_so(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt", "flask==3.1.3\n")
    stub_ok(monkeypatch)
    cli.main(["scan", str(tmp_path), "--src", str(tmp_path / "nope.py"), "--no-cache"])
    assert "No such file or directory, skipping" in capsys.readouterr().out


def test_requirements_parser_still_reads_ordinary_lines(tmp_path):
    from package_doctor.parsers.discovery import DependencySet
    deps = DependencySet()
    parse_requirements_txt(tmp_path / "requirements.txt", deps,
                           "requests==2.32.0  # pinned\nflask>=3\n\n# c\n")
    assert deps.versions == {"requests": "2.32.0", "flask": None}
    assert deps.not_analysed == {}
