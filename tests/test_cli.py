"""Command-line contracts.

`--fail-on` decides whether somebody's pipeline goes red. If it silently
returns 0 when it should return 1, a broken dependency ships and the tool is
worse than not running at all - so these are exercised end to end with the
network stubbed out.
"""

from __future__ import annotations

import json

import pytest

from package_doctor import cli
from package_doctor.models import (
    Confidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)


def finding(name: str, verdict: Verdict, direct: bool = True) -> Finding:
    return Finding(
        package=Package(name=name, version="1.0", direct=direct),
        exposure=Exposure(categories=["auth/session"], confidence=Confidence.CURATED),
        remediation=Remediation(),
        verdict=verdict,
    )


@pytest.fixture
def project(tmp_path):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\nbeta==1.0\n", encoding="utf-8")
    return tmp_path


def stub_analyzer(monkeypatch, findings):
    """Replace the network-backed analyzer with fixed results."""
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return findings

        async def analyze(self, package, now):
            return findings[0]

    monkeypatch.setattr(cli, "Analyzer", Stub)


# --- the CI contract --------------------------------------------------------

def test_fail_on_act_exits_nonzero_when_something_needs_action(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    assert cli.main(["scan", str(project), "--fail-on", "act"]) == cli.EXIT_FINDINGS


def test_fail_on_act_exits_zero_when_nothing_does(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.WATCH),
                                finding("beta", Verdict.LOW)])
    assert cli.main(["scan", str(project), "--fail-on", "act"]) == cli.EXIT_OK


def test_fail_on_watch_is_stricter(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.WATCH)])
    assert cli.main(["scan", str(project), "--fail-on", "watch"]) == cli.EXIT_FINDINGS
    assert cli.main(["scan", str(project), "--fail-on", "act"]) == cli.EXIT_OK


def test_fail_on_never_always_succeeds(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    assert cli.main(["scan", str(project), "--fail-on", "never"]) == cli.EXIT_OK


def test_unknown_and_ok_never_fail_a_build(project, monkeypatch):
    """"We could not tell" must not break someone's pipeline."""
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.UNKNOWN),
                                finding("beta", Verdict.OK)])
    assert cli.main(["scan", str(project), "--fail-on", "watch"]) == cli.EXIT_OK


def test_default_fail_level_is_act(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.WATCH)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_OK
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_FINDINGS


# --- usage errors -----------------------------------------------------------

def test_missing_directory_is_a_usage_error(tmp_path, monkeypatch):
    stub_analyzer(monkeypatch, [])
    assert cli.main(["scan", str(tmp_path / "nope")]) == cli.EXIT_USAGE


def test_a_project_with_no_dependency_files_is_a_usage_error(tmp_path, monkeypatch):
    stub_analyzer(monkeypatch, [])
    assert cli.main(["scan", str(tmp_path)]) == cli.EXIT_USAGE


def test_no_subcommand_prints_help_and_fails(capsys):
    assert cli.main([]) == cli.EXIT_USAGE
    assert "package-doctor" in capsys.readouterr().out


# --- output -----------------------------------------------------------------

def test_json_output_is_valid_and_carries_the_schema(project, monkeypatch, capsys):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    cli.main(["scan", str(project), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "package-doctor"
    assert payload["schema_version"] == 1
    assert payload["counts"] == {"act": 1}
    row = payload["findings"][0]
    assert row["name"] == "alpha"
    assert row["verdict"] == "act"
    # Contracts other tools would build on.
    assert set(row["reachability"]) == {"checked", "imported", "tests_only", "sites"}
    assert "exploitability" in row["remediation"]


def test_output_file_is_written(project, monkeypatch, tmp_path):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    out = tmp_path / "report.json"
    cli.main(["scan", str(project), "--output", str(out)])
    assert json.loads(out.read_text())["findings"][0]["name"] == "alpha"


def test_human_output_names_the_source_files(project, monkeypatch, capsys):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.ACT)])
    cli.main(["scan", str(project)])
    assert "requirements.txt" in capsys.readouterr().out


def test_direct_only_filters_transitives(project, monkeypatch):
    seen = {}

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            seen["names"] = [p.name for p in packages]
            return []

    monkeypatch.setattr(cli, "Analyzer", Stub)
    (project / "poetry.lock").write_text(
        '[[package]]\nname = "gamma"\nversion = "2.0"\n', encoding="utf-8"
    )
    cli.main(["scan", str(project), "--direct-only"])
    assert "gamma" not in seen["names"]
    assert "alpha" in seen["names"]


# --- cache ------------------------------------------------------------------

def test_cache_path_is_printed(capsys):
    assert cli.main(["cache", "path"]) == cli.EXIT_OK
    assert "package-doctor" in capsys.readouterr().out


def test_an_implausibly_large_lockfile_is_refused(tmp_path, monkeypatch):
    """Each package costs up to three requests to free, unauthenticated
    services. Nothing stops a scanned repository from declaring a hundred
    thousand of them, and firing a third of a million requests would quite
    reasonably get the user's address blocked."""
    lock = "\n".join(
        f'[[package]]\nname = "pkg{i}"\nversion = "1.0"\n' for i in range(50)
    )
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")

    called = []

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            called.append(1)
            return []

    monkeypatch.setattr(cli, "Analyzer", Stub)
    assert cli.main(["scan", str(tmp_path), "--max-packages", "10"]) == cli.EXIT_USAGE
    assert not called, "nothing should have been looked up"


def test_the_limit_can_be_raised(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\nbeta==1.0\n", encoding="utf-8")
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.OK)])
    assert cli.main(["scan", str(tmp_path), "--max-packages", "2"]) == cli.EXIT_OK


def test_version_flag_prints_package_version(capsys):
    """The bug template asks reporters for this output, so it has to exist."""
    from package_doctor import __version__

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"package-doctor {__version__}"


def test_explain_takes_the_pinned_version_with_pin(tmp_path, monkeypatch):
    """`--version` is the tool's version; the version to match is `--pin`."""
    seen = {}

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze(self, package, now):
            seen["version"] = package.version
            return finding("pillow", Verdict.WATCH)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    cli.main(["explain", "pillow", "--pin", "10.0.0", "--path", str(tmp_path), "--no-cache"])
    assert seen["version"] == "10.0.0"
    with pytest.raises(SystemExit):
        cli.main(["explain", "pillow", "--version", "10.0.0"])


def test_scan_reports_sources_relative_to_the_project(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\n", encoding="utf-8")
    (tmp_path / "requirements" / "base.txt").write_text("alpha==1.0\n", encoding="utf-8")
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.WATCH)])
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "from requirements.txt, requirements/base.txt" in out
