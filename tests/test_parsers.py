from __future__ import annotations

import json
from pathlib import Path

import pytest

from package_doctor.parsers import collect_dependencies, discover_manifests


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_requirements_pins_and_comments(tmp_path):
    write(tmp_path, "requirements.txt", """
# a comment
requests==2.31.0
flask>=2.0        # trailing comment
-r other.txt
--index-url https://example.invalid
https://example.invalid/pkg.tar.gz
Django==4.2.1 ; python_version >= "3.8"
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["requests"] == "2.31.0"
    assert deps.versions["flask"] is None
    assert deps.versions["django"] == "4.2.1"
    assert "requests" in deps.direct


def test_pep621_and_optional_and_groups(tmp_path):
    write(tmp_path, "pyproject.toml", """
[project]
name = "demo"
dependencies = ["httpx>=0.27", "pyyaml==6.0.1"]
[project.optional-dependencies]
dev = ["pytest>=8"]
[dependency-groups]
lint = ["ruff==0.5.0"]
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["pyyaml"] == "6.0.1"
    assert {"httpx", "pytest", "ruff"} <= set(deps.versions)


def test_uv_lock_marks_transitive(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="d"\ndependencies=["requests"]\n')
    write(tmp_path, "uv.lock", """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "charset-normalizer"
version = "3.3.2"
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["charset-normalizer"] == "3.3.2"
    assert "requests" in deps.direct
    assert "charset-normalizer" not in deps.direct


def test_a_lockfile_forked_by_python_version_scans_the_newest(tmp_path):
    # GitGuardian/ggshield: uv lists the Python 3.9 fork first, and the first
    # entry used to win - four act verdicts that a 3.10+ install does not have.
    write(tmp_path, "uv.lock", """
[[package]]
name = "urllib3"
version = "2.6.3"
resolution-markers = ["python_full_version < '3.10'"]

[[package]]
name = "urllib3"
version = "2.7.0"
resolution-markers = ["python_full_version >= '3.10'"]
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["urllib3"] == "2.7.0"
    assert deps.other_versions["urllib3"] == {"2.6.3"}


def test_the_newest_wins_whichever_order_the_versions_arrive_in(tmp_path):
    write(tmp_path, "poetry.lock", """
[[package]]
name = "cryptography"
version = "46.0.7"

[[package]]
name = "cryptography"
version = "45.0.7"
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["cryptography"] == "46.0.7"
    assert deps.other_versions["cryptography"] == {"45.0.7"}


@pytest.mark.parametrize("pinned", ["2.99.0", "2.0.0"])
@pytest.mark.parametrize("reverse", [False, True])
def test_a_lockfile_beats_a_different_pin_in_another_file(tmp_path, pinned, reverse):
    # Newer: the-paperless-project/paperless's requirements.txt and Pipfile.lock
    # disagree on 49 pins and the Dockerfile installs the lock. Older:
    # cohere-python pins requests==2.0.0 beside a poetry.lock at 2.34.2.
    write(tmp_path, "requirements.txt", f"requests=={pinned}\n")
    write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.34.2"\n')
    paths = discover_manifests(tmp_path)
    deps = collect_dependencies(paths[::-1] if reverse else paths, root=tmp_path)
    assert deps.versions["requests"] == "2.34.2"
    assert deps.other_versions["requests"] == {pinned}


def test_one_version_spelled_two_ways_is_not_a_fork(tmp_path):
    write(tmp_path, "requirements.txt", "six==1.16\n")
    write(tmp_path, "requirements-dev.txt", "six==1.16.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert "six" not in deps.other_versions


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-8-sig"])
def test_requirements_saved_by_windows_tools_are_read(tmp_path, encoding):
    # `pip freeze > requirements.txt` in PowerShell writes UTF-16 with a byte
    # order mark; microsoft/Table-Pretraining ships one and it read as empty.
    body = "# frozen\r\nrequests==2.26.0\r\nurllib3==1.26.6\r\n"
    (tmp_path / "requirements.txt").write_bytes(body.encode(encoding))
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions == {"requests": "2.26.0", "urllib3": "1.26.6"}


def test_poetry_lock(tmp_path):
    write(tmp_path, "poetry.lock", """
[[package]]
name = "Jinja2"
version = "3.1.4"
""")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["jinja2"] == "3.1.4"


def test_pipfile_lock(tmp_path):
    write(tmp_path, "Pipfile.lock", json.dumps({
        "default": {"urllib3": {"version": "==1.26.18"}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }))
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert deps.versions["urllib3"] == "1.26.18"
    assert deps.versions["pytest"] == "8.0.0"


def test_names_are_normalised_across_files(tmp_path):
    write(tmp_path, "requirements.txt", "Flask_Login==0.6.3\n")
    write(tmp_path, "poetry.lock", '[[package]]\nname = "flask-login"\nversion = "0.6.3"\n')
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert list(deps.versions) == ["flask-login"]


def test_toolchain_packages_are_analysed_like_any_other(tmp_path):
    """pip and setuptools used to be dropped here without a word. A pinned
    old setuptools carries CVE-2024-6345, and a report that silently left
    it out was wrong exactly where it looked complete."""
    write(tmp_path, "requirements.txt", "pip==24.0\nsetuptools==70.0\nrequests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert set(deps.versions) == {"pip", "setuptools", "requests"}


def test_malformed_files_do_not_crash(tmp_path):
    write(tmp_path, "pyproject.toml", "this is [not valid toml")
    write(tmp_path, "requirements.txt", "!!! not a requirement\n")
    assert len(collect_dependencies(discover_manifests(tmp_path))) == 0


# --- requirements includes and the requirements/ directory -------------------

def test_a_requirements_directory_is_discovered(tmp_path):
    """The pip-tools and Django layout: nothing at the root but a directory."""
    (tmp_path / "requirements").mkdir()
    write(tmp_path / "requirements", "base.txt", "requests==2.31.0\n")
    write(tmp_path / "requirements", "dev.txt", "pytest==8.0.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"requests": "2.31.0", "pytest": "8.0.0"}
    assert deps.origins["requests"] == {"requirements/base.txt"}


def test_r_includes_are_followed_relative_to_the_including_file(tmp_path):
    (tmp_path / "requirements").mkdir()
    write(tmp_path, "requirements.txt", "-r requirements/prod.txt\nlocal-only==1.0\n")
    write(tmp_path / "requirements", "prod.txt", "--requirement=base.txt\ngunicorn==21.2.0\n")
    write(tmp_path / "requirements", "base.txt", "requests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {
        "local-only": "1.0", "gunicorn": "21.2.0", "requests": "2.31.0",
    }
    assert deps.origins["requests"] == {"requirements/base.txt"}
    assert not deps.refused


def test_a_file_reached_twice_is_read_once(tmp_path):
    """Discovered under requirements/ and also included from the root."""
    (tmp_path / "requirements").mkdir()
    write(tmp_path, "requirements.txt", "-r requirements/base.txt\n")
    write(tmp_path / "requirements", "base.txt", "requests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert [p.name for p in deps.sources].count("base.txt") == 1


def test_an_include_outside_the_project_is_refused(tmp_path):
    """A checkout must not be able to read files beyond its own directory."""
    project = tmp_path / "project"
    project.mkdir()
    write(tmp_path, "secret.txt", "leaked==1.0\n")
    write(project, "requirements.txt", "-r ../secret.txt\nrequests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(project), root=project)
    assert set(deps.versions) == {"requests"}
    assert [p.name for p in deps.refused] == ["secret.txt"]


def test_an_include_cycle_terminates(tmp_path):
    write(tmp_path, "requirements.txt", "-r requirements-a.txt\n")
    write(tmp_path, "requirements-a.txt", "-r requirements.txt\nrequests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"requests": "2.31.0"}


def test_an_include_chain_deeper_than_the_limit_is_refused(tmp_path):
    from package_doctor.parsers.discovery import MAX_INCLUDE_DEPTH
    depth = MAX_INCLUDE_DEPTH + 2
    write(tmp_path, "requirements.txt", "-r requirements-0.txt\n")
    for i in range(depth):
        write(tmp_path, f"requirements-{i}.txt", f"-r requirements-{i + 1}.txt\n")
    write(tmp_path, f"requirements-{depth}.txt", "requests==2.31.0\n")
    # Every file is also discovered at the root, so the leaf is still read;
    # the point is that the chain itself stops and says so.
    deps = collect_dependencies([tmp_path / "requirements.txt"], root=tmp_path)
    assert not deps.versions
    assert deps.refused, "the chain was cut, and reported"


def test_constraints_files_are_not_followed(tmp_path):
    """-c pins what is installed; it does not install anything."""
    write(tmp_path, "requirements.txt", "-c constraints.txt\nrequests==2.31.0\n")
    write(tmp_path, "constraints.txt", "urllib3==2.0.7\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"requests"}


def test_a_missing_include_is_reported_not_fatal(tmp_path):
    write(tmp_path, "requirements.txt", "-r nope.txt\nrequests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"requests"}
    assert [p.name for p in deps.refused] == ["nope.txt"]


# --- the project's own package is not a dependency ---------------------------

def test_the_projects_own_name_is_skipped_not_assessed(tmp_path):
    """mlflow's lockfile lists mlflow, and the tool put it at the top of
    mlflow's own report with 36 advisories against it."""
    write(tmp_path, "pyproject.toml",
          '[project]\nname = "mlflow"\ndependencies = ["requests==2.31.0"]\n')
    write(tmp_path, "uv.lock", """
[[package]]
name = "mlflow"
version = "3.0.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"requests"}
    assert deps.local == {"mlflow"}


def test_uv_workspace_members_and_local_paths_are_skipped(tmp_path):
    write(tmp_path, "uv.lock", """
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "backend" }

[[package]]
name = "shared"
version = "0.1.0"
source = { virtual = "libs/shared" }

[[package]]
name = "vendored"
version = "1.0"
source = { directory = "vendor/thing" }

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
""")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"urllib3"}
    assert deps.local == {"app", "shared", "vendored"}


def test_poetry_directory_sources_are_skipped(tmp_path):
    write(tmp_path, "poetry.lock", """
[[package]]
name = "local-lib"
version = "0.1.0"

[package.source]
type = "directory"
url = "libs/local-lib"

[[package]]
name = "urllib3"
version = "2.0.7"
""")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"urllib3"}
    assert deps.local == {"local-lib"}


def test_marking_local_after_the_fact_removes_an_earlier_entry(tmp_path):
    """A requirements file can list the project itself (`-e .` is skipped, but
    a bare name is not); pyproject is discovered after it and must still win."""
    write(tmp_path, "requirements.txt", "myproj==1.0\nrequests==2.31.0\n")
    write(tmp_path, "pyproject.toml", '[project]\nname = "myproj"\n')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert set(deps.versions) == {"requests"}
    assert "myproj" not in deps.direct


# --- a wildcard is a range ---------------------------------------------------

@pytest.mark.parametrize("line", ["click==8.*", "click == 8.*", "click===8.*"])
def test_a_wildcard_pin_is_not_a_version(tmp_path, line):
    """`click==8.*` stored as the version "8.*" reached OSV as a literal and
    matched nothing, which read as a package with no advisories."""
    write(tmp_path, "requirements.txt", line + "\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"click": None}


def test_wildcards_in_every_parser_are_unpinned(tmp_path):
    write(tmp_path, "pyproject.toml", """
[project]
dependencies = ["httpcore==1.*"]
[tool.poetry.dependencies]
pygments = "=2.*"
""")
    write(tmp_path, "Pipfile.lock", '{"default": {"socksio": {"version": "==1.*"}}}')
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"httpcore": None, "pygments": None, "socksio": None}


# --- requirements/<env>/*.txt ------------------------------------------------

def test_requirements_one_level_deeper_are_discovered(tmp_path):
    """text-generation-webui: requirements/full/requirements.txt and
    requirements/portable/requirements.txt, nothing at the root."""
    for env in ("full", "portable"):
        (tmp_path / "requirements" / env).mkdir(parents=True)
    write(tmp_path / "requirements" / "full", "requirements.txt", "torch==2.13.0\n")
    write(tmp_path / "requirements" / "portable", "requirements.txt", "gradio==5.0.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path), root=tmp_path)
    assert deps.versions == {"torch": "2.13.0", "gradio": "5.0.0"}
    assert deps.origins["torch"] == {"requirements/full/requirements.txt"}


def test_discovery_does_not_go_deeper_than_one_level(tmp_path):
    (tmp_path / "requirements" / "a" / "b").mkdir(parents=True)
    write(tmp_path / "requirements" / "a" / "b", "deep.txt", "requests==2.31.0\n")
    assert not collect_dependencies(discover_manifests(tmp_path), root=tmp_path).versions
