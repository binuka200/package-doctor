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

def at_boundary(name: str, verdict: Verdict) -> Finding:
    return finding(name, verdict)


def away(name: str, verdict: Verdict) -> Finding:
    f = finding(name, verdict)
    f.exposure = Exposure(categories=[], confidence=Confidence.CURATED)
    return f


@pytest.mark.parametrize("verdict", [Verdict.EXPLOITED, Verdict.REPLACE, Verdict.UPGRADE])
def test_the_default_fails_at_a_reviewed_boundary(project, monkeypatch, verdict):
    stub_analyzer(monkeypatch, [at_boundary("alpha", verdict)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_FINDINGS


@pytest.mark.parametrize("verdict", [Verdict.REPLACE, Verdict.UPGRADE, Verdict.MITIGATE])
def test_the_default_does_not_fail_away_from_a_boundary(project, monkeypatch, verdict):
    """The same facts, where the map says no attacker-controlled data flows.
    Worth knowing; not worth turning a pipeline red."""
    stub_analyzer(monkeypatch, [away("alpha", verdict)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_OK


def test_exploited_fails_wherever_it_is_found(project, monkeypatch):
    """Active exploitation does not wait on the exposure map."""
    stub_analyzer(monkeypatch, [away("alpha", Verdict.EXPLOITED)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_FINDINGS


def test_mitigate_never_fails_even_at_a_boundary(project, monkeypatch):
    """No release anywhere fixes it, so a red build cannot be turned green -
    which is how a scanner gets switched off."""
    stub_analyzer(monkeypatch, [at_boundary("alpha", Verdict.MITIGATE)])
    assert cli.main(["scan", str(project)]) == cli.EXIT_OK
    assert cli.main(["scan", str(project), "--fail-on", "vulnerable"]) == cli.EXIT_FINDINGS


def test_quiet_never_fails(project, monkeypatch):
    stub_analyzer(monkeypatch, [at_boundary("alpha", Verdict.QUIET)])
    for level in ("boundary", "vulnerable"):
        assert cli.main(["scan", str(project), "--fail-on", level]) == cli.EXIT_OK
    assert cli.main(["scan", str(project), "--fail-on", "all"]) == cli.EXIT_FINDINGS


def test_the_stricter_levels_ignore_the_boundary(project, monkeypatch):
    stub_analyzer(monkeypatch, [away("alpha", Verdict.UPGRADE)])
    assert cli.main(["scan", str(project), "--fail-on", "boundary"]) == cli.EXIT_OK
    assert cli.main(["scan", str(project), "--fail-on", "vulnerable"]) == cli.EXIT_FINDINGS
    assert cli.main(["scan", str(project), "--fail-on", "exploited"]) == cli.EXIT_OK


def test_the_old_level_names_still_work(project, monkeypatch):
    """`--fail-on act` in somebody's pipeline must not become a usage error."""
    stub_analyzer(monkeypatch, [at_boundary("alpha", Verdict.UPGRADE)])
    assert cli.main(["scan", str(project), "--fail-on", "act"]) == cli.EXIT_FINDINGS
    stub_analyzer(monkeypatch, [away("alpha", Verdict.UPGRADE)])
    assert cli.main(["scan", str(project), "--fail-on", "act"]) == cli.EXIT_OK
    assert cli.main(["scan", str(project), "--fail-on", "watch"]) == cli.EXIT_FINDINGS


def test_fail_on_never_always_succeeds(project, monkeypatch):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.EXPLOITED)])
    assert cli.main(["scan", str(project), "--fail-on", "never"]) == cli.EXIT_OK


def test_unchecked_and_ok_never_fail_a_build(project, monkeypatch):
    """"We could not tell" must not break someone's pipeline."""
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.UNCHECKED),
                                finding("beta", Verdict.OK)])
    assert cli.main(["scan", str(project), "--fail-on", "review"]) == cli.EXIT_OK


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
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.REPLACE)])
    cli.main(["scan", str(project), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "package-doctor"
    assert payload["schema_version"] == 3
    assert payload["counts"] == {"replace": 1}
    row = payload["findings"][0]
    assert row["name"] == "alpha"
    assert row["verdict"] == "replace"
    # Contracts other tools would build on.
    assert set(row["reachability"]) == {"checked", "imported", "tests_only", "sites"}
    assert "exploitability" in row["remediation"]


def test_output_file_is_written(project, monkeypatch, tmp_path):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.REPLACE)])
    out = tmp_path / "report.json"
    cli.main(["scan", str(project), "--output", str(out)])
    assert json.loads(out.read_text())["findings"][0]["name"] == "alpha"


def test_human_output_names_the_source_files(project, monkeypatch, capsys):
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.REPLACE)])
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
            return finding("pillow", Verdict.MITIGATE)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    cli.main(["explain", "pillow", "--pin", "10.0.0", "--path", str(tmp_path), "--no-cache"])
    assert seen["version"] == "10.0.0"
    with pytest.raises(SystemExit):
        cli.main(["explain", "pillow", "--version", "10.0.0"])


def _capture_explained(monkeypatch):
    seen = {}

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze(self, package, now):
            seen["package"] = package
            return finding(package.name, Verdict.MITIGATE)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    return seen


def test_explain_reads_a_pip_style_pin_from_the_name(tmp_path, monkeypatch):
    """`explain bleach==6.4.0` went to PyPI as the name "bleach==6.4.0" and
    came back not found."""
    seen = _capture_explained(monkeypatch)
    cli.main(["explain", "bleach==6.4.0", "--path", str(tmp_path), "--no-cache"])
    assert seen["package"].name == "bleach"
    assert seen["package"].version == "6.4.0"


def test_explain_takes_a_range_in_the_name_as_the_specifier(tmp_path, monkeypatch):
    seen = _capture_explained(monkeypatch)
    cli.main(["explain", "bleach>=6,<7", "--path", str(tmp_path), "--no-cache"])
    assert seen["package"].name == "bleach"
    assert seen["package"].version is None
    assert seen["package"].specifier == "<7,>=6"


def test_explain_the_pin_in_the_name_beats_the_lockfile(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("bleach==6.0.0\n", encoding="utf-8")
    seen = _capture_explained(monkeypatch)
    cli.main(["explain", "bleach==6.4.0", "--path", str(tmp_path), "--no-cache"])
    assert seen["package"].version == "6.4.0"


def test_explain_refuses_two_different_pins(tmp_path, monkeypatch, capsys):
    seen = _capture_explained(monkeypatch)
    code = cli.main(
        ["explain", "bleach==6.4.0", "--pin", "6.3.0", "--path", str(tmp_path), "--no-cache"]
    )
    assert code == cli.EXIT_USAGE
    assert "Two versions given" in capsys.readouterr().out
    assert not seen


def test_explain_accepts_the_same_pin_twice(tmp_path, monkeypatch):
    seen = _capture_explained(monkeypatch)
    cli.main(
        ["explain", "bleach==6.4.0", "--pin", "6.4.0", "--path", str(tmp_path), "--no-cache"]
    )
    assert seen["package"].version == "6.4.0"


def test_explain_rejects_a_name_that_is_not_a_requirement(tmp_path, monkeypatch, capsys):
    seen = _capture_explained(monkeypatch)
    code = cli.main(["explain", "not a name", "--path", str(tmp_path), "--no-cache"])
    assert code == cli.EXIT_USAGE
    assert not seen


def test_scan_writes_an_empty_report_when_no_dependencies_are_found(tmp_path, monkeypatch):
    """huggingface/transformers computes install_requires, so nothing could be
    read; the scan exited 0 without writing -o, and the step that read the
    JSON failed on a missing file. The report now exists and says why, and
    the scan fails: nothing found because nothing could be read is not clean."""
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nfrom deps import REQS\nsetup(install_requires=REQS)\n",
        encoding="utf-8",
    )
    stub_analyzer(monkeypatch, [])
    out, sarif = tmp_path / "report.json", tmp_path / "report.sarif"
    code = cli.main(["scan", str(tmp_path), "-o", str(out), "--sarif", str(sarif),
                     "--no-cache"])
    assert code == cli.EXIT_FINDINGS
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["unread"] == [
        {"file": "setup.py", "reason": "install_requires is computed in Python"}
    ]
    assert sarif.exists()


def test_fail_on_never_passes_a_scan_with_nothing_readable(tmp_path, monkeypatch):
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nfrom deps import REQS\nsetup(install_requires=REQS)\n",
        encoding="utf-8",
    )
    stub_analyzer(monkeypatch, [])
    assert cli.main(["scan", str(tmp_path), "--no-cache"]) == cli.EXIT_FINDINGS
    assert cli.main(["scan", str(tmp_path), "--no-cache", "--fail-on", "never"]) == cli.EXIT_OK


def test_a_project_that_declares_nothing_still_passes(tmp_path, monkeypatch):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n",
                                       encoding="utf-8")
    stub_analyzer(monkeypatch, [])
    assert cli.main(["scan", str(tmp_path), "--no-cache"]) == cli.EXIT_OK


def test_an_approximated_setup_py_is_named_in_the_report(tmp_path, monkeypatch):
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n_deps = ['flask']\n"
        "setup(install_requires=[d for d in _deps])\n",
        encoding="utf-8",
    )
    stub_analyzer(monkeypatch, [])
    out = tmp_path / "report.json"
    cli.main(["scan", str(tmp_path), "-o", str(out), "--no-cache", "--no-reachability"])
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["unread"] == []
    assert payload["approximated"] == [{
        "file": "setup.py",
        "how": "install_requires is computed in Python, so the scan reads the literal "
               "list _deps it is built from",
    }]


def test_scan_reports_sources_relative_to_the_project(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\n", encoding="utf-8")
    (tmp_path / "requirements" / "base.txt").write_text("alpha==1.0\n", encoding="utf-8")
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.MITIGATE)])
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "from requirements.txt, requirements/base.txt" in out


def test_scan_says_which_local_packages_it_skipped(tmp_path, monkeypatch, capsys):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "myproj"\ndependencies = ["alpha==1.0"]\n', encoding="utf-8"
    )
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.MITIGATE)])
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "Skipped myproj" in out and "own package" in out


def test_json_on_stdout_stays_valid_when_there_are_notes(tmp_path, monkeypatch, capsys):
    """The "Skipped myproj: this project's own package" note landed on stdout
    ahead of the JSON and broke every pipeline that parsed it."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "myproj"\ndependencies = ["alpha==1.0"]\n', encoding="utf-8"
    )
    # Over the cap below; pyproject.toml, at ~50 bytes, stays under it.
    (tmp_path / "uv.lock").write_text("x" * 200, encoding="utf-8")
    from package_doctor.parsers import discovery
    monkeypatch.setattr(
        cli, "collect_dependencies",
        lambda paths, **kw: discovery.collect_dependencies(paths, max_bytes=100, **kw),
    )
    stub_analyzer(monkeypatch, [finding("alpha", Verdict.MITIGATE)])
    cli.main(["scan", str(tmp_path), "--json", "--no-reachability", "--no-cache"])
    out, err = capsys.readouterr()
    payload = json.loads(out)
    assert payload["counts"]["mitigate"] == 1
    assert "Skipped myproj" in err and "Not read:" in err
