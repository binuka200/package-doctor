"""Nested discovery, setup.cfg, and --src on explain.

`scan .` used to exit with "No dependency files found" for a project whose
requirements live in configs/. The fallback that fixes it is bounded on
purpose: two levels down, never into tests, docs, examples or vendored
code, and only when the root itself has nothing. setup.cfg is read
because it is declarative; setup.py is not, because a computed
install_requires is invisible to a parser and a partial answer that looks
complete is the failure this tool exists to avoid.
"""

from __future__ import annotations

import json
from pathlib import Path

from package_doctor import cli
from package_doctor.models import Confidence, Exposure, Finding, Remediation, Verdict
from package_doctor.parsers import collect_dependencies, discover_manifests, discover_nested
from package_doctor.parsers.discovery import NESTED_DEPTH, is_dependency_file


def write(root: Path, name: str, text: str = "flask==3.1.3\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rel(root: Path, paths: list[Path]) -> list[str]:
    return [p.relative_to(root).as_posix() for p in paths]


# --- the fallback search -----------------------------------------------------

def test_nested_files_are_found_shallowest_first(tmp_path):
    write(tmp_path, "configs/requirements.txt")
    write(tmp_path, "services/api/pyproject.toml", '[project]\nname="api"\n')
    assert discover_manifests(tmp_path) == []
    assert rel(tmp_path, discover_nested(tmp_path)) == [
        "configs/requirements.txt", "services/api/pyproject.toml",
    ]


def test_the_search_stops_at_two_levels(tmp_path):
    write(tmp_path, "a/b/c/requirements.txt")
    assert discover_nested(tmp_path) == []
    assert NESTED_DEPTH == 2


def test_tests_docs_examples_and_vendored_code_are_never_entered(tmp_path):
    for d in ("tests", "test", "docs", "examples", "fixtures", "vendor", "third_party",
              "node_modules", ".venv", "build", ".hidden"):
        write(tmp_path, f"{d}/requirements.txt")
    write(tmp_path, "tests/fixtures/sample/requirements.txt")
    assert discover_nested(tmp_path) == []


def test_a_root_with_files_never_falls_back(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt")
    write(tmp_path, "configs/requirements.txt", "evil==1\n")
    stub(monkeypatch)
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "from requirements.txt" in out
    assert "configs" not in out


def stub(monkeypatch, seen: dict | None = None):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            if seen is not None:
                seen.update({p.name: p.import_sites for p in packages})
            return [Finding(package=p, exposure=Exposure(categories=[],
                            confidence=Confidence.CURATED), remediation=Remediation(),
                            verdict=Verdict.OK) for p in packages]

        async def analyze(self, package, now):
            if seen is not None:
                seen[package.name] = package.import_sites
            return Finding(package=package, exposure=Exposure(), remediation=Remediation(),
                           verdict=Verdict.OK)

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_scan_of_the_root_now_works_for_a_configs_layout(tmp_path, monkeypatch, capsys):
    write(tmp_path, "configs/requirements.txt")
    stub(monkeypatch)
    assert cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "No dependency files at the root; using configs/requirements.txt" in out
    assert "from configs/requirements.txt" in out


def test_nothing_anywhere_is_a_usage_error_that_says_where_it_looked(tmp_path, monkeypatch, capsys):
    write(tmp_path, "tests/requirements.txt")
    stub(monkeypatch)
    assert cli.main(["scan", str(tmp_path), "--no-cache"]) == cli.EXIT_USAGE
    out = capsys.readouterr().out
    assert "No dependency files found" in out
    assert "up to 2 directories down" in out and "tests, docs, examples" in out


# --- setup.cfg ---------------------------------------------------------------

SETUP_CFG = """
[metadata]
name = myproj

[options]
install_requires =
    requests>=2.28
    pillow==10.0.0
    internal @ git+ssh://git@github.com/org/internal.git

[options.extras_require]
dev =
    pytest
docs = sphinx>=7
"""


def test_setup_cfg_install_requires_and_extras_are_read(tmp_path):
    write(tmp_path, "setup.cfg", SETUP_CFG)
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"requests": None, "pillow": "10.0.0", "pytest": None, "sphinx": None}
    assert deps.specifiers == {"requests": ">=2.28", "sphinx": ">=7"}
    assert deps.not_analysed == {"internal": "git"}
    assert "myproj" in deps.local
    assert is_dependency_file(tmp_path / "setup.cfg")


def test_a_setup_cfg_without_dependencies_adds_nothing(tmp_path):
    write(tmp_path, "setup.cfg", "[flake8]\nmax-line-length = 100\n")
    write(tmp_path, "requirements.txt")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"flask": "3.1.3"}


def test_a_malformed_setup_cfg_is_ignored(tmp_path):
    write(tmp_path, "setup.cfg", "[options\ninstall_requires = x\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {}


def test_setup_py_is_deliberately_not_read(tmp_path):
    write(tmp_path, "setup.py", "from setuptools import setup\nsetup(install_requires=['flask'])\n")
    assert discover_manifests(tmp_path) == []
    assert discover_nested(tmp_path) == []


# --- --src on explain --------------------------------------------------------

def test_explain_accepts_src_and_matches_scan(tmp_path, monkeypatch):
    write(tmp_path, "configs/requirements.txt", "flask==3.1.3\npasslib==1.7.4\n")
    write(tmp_path, "core/__init__.py", "")
    write(tmp_path, "core/models/user.py", "import passlib\n")
    monkeypatch.chdir(tmp_path)
    seen: dict = {}
    stub(monkeypatch, seen)
    cli.main(["scan", str(tmp_path / "configs"), "--src", str(tmp_path / "core"), "--no-cache"])
    from_scan = seen["passlib"]
    seen.clear()
    cli.main(["explain", "passlib", "--path", str(tmp_path / "configs"),
              "--src", str(tmp_path / "core"), "--no-cache", "--json"])
    assert seen["passlib"] == from_scan == ["core/models/user.py:1"]


def test_explain_without_src_still_auto_detects(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt", "passlib==1.7.4\n")
    write(tmp_path, "core/__init__.py", "import passlib\n")
    stub(monkeypatch)
    cli.main(["explain", "passlib", "--path", str(tmp_path), "--no-cache", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["reachability"]["sites"] == ["core/__init__.py:1"]


def test_explain_reports_a_missing_src(tmp_path, monkeypatch, capsys):
    write(tmp_path, "requirements.txt", "passlib==1.7.4\n")
    stub(monkeypatch)
    cli.main(["explain", "passlib", "--path", str(tmp_path), "--src", str(tmp_path / "nope"),
              "--no-cache"])
    assert "No such file or directory, skipping" in capsys.readouterr().out
