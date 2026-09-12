from __future__ import annotations

import json
from pathlib import Path

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


def test_toolchain_packages_are_ignored(tmp_path):
    write(tmp_path, "requirements.txt", "pip==24.0\nsetuptools==70.0\nrequests==2.31.0\n")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert set(deps.versions) == {"requests"}


def test_malformed_files_do_not_crash(tmp_path):
    write(tmp_path, "pyproject.toml", "this is [not valid toml")
    write(tmp_path, "requirements.txt", "!!! not a requirement\n")
    assert len(collect_dependencies(discover_manifests(tmp_path))) == 0
