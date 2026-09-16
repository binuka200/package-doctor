"""The PostToolUse hook: what an edit to a dependency file just added.

An agent that writes a name into pyproject.toml and then runs `uv sync`
never types the name into a shell command, so the install hook cannot see
it. This path reads the file after the edit and checks only what the edit
introduced. Two things are pinned here: the diff is against the lockfiles
and the committed file, so nothing nags about packages the agent did not
touch; and the hook never exits 2, because the edit has already happened.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import subprocess
from pathlib import Path

import pytest

from package_doctor import cli
from package_doctor.guard import added_requirements, is_manifest
from package_doctor.models import (
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)

NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.invalid")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["requests>=2", "pillow==10.0.0"]\n',
        encoding="utf-8",
    )
    git(tmp_path, "add", "pyproject.toml")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


# --- which files -------------------------------------------------------------

@pytest.mark.parametrize("name, expected", [
    ("pyproject.toml", True), ("Pipfile", True), ("requirements.txt", True),
    ("requirements-dev.txt", True), ("requirements/base.txt", True),
    ("uv.lock", False), ("poetry.lock", False), ("Pipfile.lock", False),
    ("src/app.py", False), ("README.md", False),
])
def test_only_hand_written_dependency_files_count(name, expected):
    assert is_manifest(Path("/p") / name) is expected


# --- the diff ---------------------------------------------------------------

def test_only_names_the_edit_introduced_are_returned(repo):
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\n'
        'dependencies = ["requests>=2", "pillow==10.0.0", "reqeusts", "django<5"]\n',
        encoding="utf-8",
    )
    assert added_requirements(repo / "pyproject.toml", repo) == ["django<5", "reqeusts"]


def test_an_edit_that_adds_nothing_checks_nothing(repo):
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["pillow==10.0.0", "requests>=2"]\n',
        encoding="utf-8",
    )
    assert added_requirements(repo / "pyproject.toml", repo) == []


def test_names_already_in_a_lockfile_are_not_new(repo):
    (repo / "uv.lock").write_text('[[package]]\nname = "httpx"\nversion = "0.28.1"\n',
                                  encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["requests>=2", "pillow==10.0.0", "httpx"]\n',
        encoding="utf-8",
    )
    assert added_requirements(repo / "pyproject.toml", repo) == []


def test_requirements_files_are_diffed_too(repo):
    (repo / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    git(repo, "add", "requirements.txt")
    git(repo, "commit", "-q", "-m", "reqs")
    (repo / "requirements.txt").write_text("requests==2.32.0\nlegacy-auth==2.1.0\n",
                                           encoding="utf-8")
    assert added_requirements(repo / "requirements.txt", repo) == ["legacy-auth==2.1.0"]


def test_without_git_or_a_lockfile_everything_is_new(tmp_path):
    (tmp_path / "requirements.txt").write_text("alpha==1\nbeta\n", encoding="utf-8")
    assert added_requirements(tmp_path / "requirements.txt", tmp_path) == ["alpha==1", "beta"]


def test_a_missing_or_non_manifest_file_yields_nothing(repo):
    assert added_requirements(repo / "gone.txt", repo) == []
    (repo / "notes.md").write_text("pip install requests\n", encoding="utf-8")
    assert added_requirements(repo / "notes.md", repo) == []


# --- through the hook -------------------------------------------------------

def finding(name: str, verdict: Verdict, reasons: list[str], error: str | None = None) -> Finding:
    return Finding(
        package=Package(name=name, version="1.0"),
        exposure=Exposure(categories=["auth/session"], confidence=Confidence.CURATED),
        remediation=Remediation(first_release=NOW - dt.timedelta(days=900)),
        verdict=verdict,
        reasons=[Evidence(r) for r in reasons],
        error=error,
    )


def stub(monkeypatch, findings):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            by_name = {f.package.name: f for f in findings}
            return [by_name[p.name] for p in packages]

    monkeypatch.setattr(cli, "Analyzer", Stub)


def event(path: Path, root: Path, tool: str = "Edit") -> str:
    return json.dumps({
        "hook_event_name": "PostToolUse", "tool_name": tool, "cwd": str(root),
        "tool_input": {"file_path": str(path), "old_string": "x", "new_string": "y"},
        "tool_result": "ok",
    })


def run_hook(monkeypatch, stdin: str) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(["hook", "claude-code", "--no-cache"])


def test_an_added_bad_package_reaches_the_model_as_context_not_a_block(repo, monkeypatch, capsys):
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\n'
        'dependencies = ["requests>=2", "pillow==10.0.0", "legacy-auth==2.1.0"]\n',
        encoding="utf-8",
    )
    stub(monkeypatch, [finding("legacy-auth", Verdict.REPLACE, ["repository is archived"])])
    code = run_hook(monkeypatch, event(repo / "pyproject.toml", repo))
    out, err = capsys.readouterr()
    assert code == 0, "the edit already happened; PostToolUse cannot block"
    payload = json.loads(out)
    assert "BLOCK legacy-auth" in payload["systemMessage"]
    assert "pyproject.toml" in payload["systemMessage"]
    assert "Remove the blocked package" in payload["systemMessage"]
    assert payload["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert "permissionDecision" not in payload["hookSpecificOutput"]


def test_only_the_new_name_is_looked_up(repo, monkeypatch, capsys):
    seen = []

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            seen.extend(p.name for p in packages)
            found = [finding(p.name, Verdict.OK, []) for p in packages]
            for f in found:
                # Not at a boundary: a healthy boundary package still warns.
                f.exposure = Exposure(categories=[], confidence=Confidence.CURATED)
            return found

    monkeypatch.setattr(cli, "Analyzer", Stub)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["requests>=2", "pillow==10.0.0", "six"]\n',
        encoding="utf-8",
    )
    assert run_hook(monkeypatch, event(repo / "pyproject.toml", repo, tool="Write")) == 0
    assert seen == ["six"]
    assert capsys.readouterr().out == "", "nothing flagged, nothing said"


def test_edits_to_other_files_are_ignored(repo, monkeypatch, capsys):
    called = []

    class Stub:
        def __init__(self, *a, **kw):
            called.append(1)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    (repo / "app.py").write_text("import reqeusts\n", encoding="utf-8")
    assert run_hook(monkeypatch, event(repo / "app.py", repo)) == 0
    assert run_hook(monkeypatch, json.dumps({"tool_name": "Edit", "tool_input": {}})) == 0
    assert not called
    assert capsys.readouterr().out == ""


def test_the_edit_hook_fails_open(repo, monkeypatch, capsys):
    class Boom:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            raise RuntimeError("upstream exploded")

    monkeypatch.setattr(cli, "Analyzer", Boom)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["requests>=2", "pillow==10.0.0", "six"]\n',
        encoding="utf-8",
    )
    assert run_hook(monkeypatch, event(repo / "pyproject.toml", repo)) == 0
    assert "could not check" in json.loads(capsys.readouterr().out)["systemMessage"]
