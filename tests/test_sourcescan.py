"""Import-graph reachability, and the limit it must never overstep."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from package_doctor.models import (
    AdvisoryHistory,
    Confidence,
    Exposure,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.risk import assess
from package_doctor.sourcescan import build_index, detect_source_roots, extract_imports

NOW = dt.datetime(2026, 9, 12, tzinfo=dt.timezone.utc)


def write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --- extraction -------------------------------------------------------------

def test_extracts_plain_and_from_imports_with_line_numbers():
    found = extract_imports("import os\n\nfrom yaml import safe_load\n")
    assert ("os", 1) in found
    assert ("yaml", 3) in found


def test_takes_the_top_level_module_only():
    assert extract_imports("from a.b.c import d\n") == [("a", 1)]
    assert extract_imports("import a.b.c\n") == [("a", 1)]


def test_relative_imports_are_not_dependencies():
    assert extract_imports("from . import sibling\nfrom .mod import thing\n") == []


def test_imports_inside_functions_are_found():
    found = extract_imports("def f():\n    import requests\n    return requests\n")
    assert ("requests", 2) in found


def test_aliased_imports_resolve_to_the_real_module():
    assert extract_imports("import numpy as np\n") == [("numpy", 1)]


# --- indexing ---------------------------------------------------------------

def test_maps_import_names_to_distribution_names(tmp_path):
    write(tmp_path, "app.py", "from PIL import Image\nimport yaml\nimport jwt\n")
    index = build_index(tmp_path, known_packages={"pillow", "pyyaml", "pyjwt"})
    assert index.for_package("pillow")
    assert index.for_package("pyyaml")
    assert index.for_package("pyjwt")


def test_records_file_and_line(tmp_path):
    write(tmp_path, "pkg/handler.py", "import os\n\n\nimport requests\n")
    index = build_index(tmp_path, known_packages={"requests"})
    site = index.for_package("requests")[0]
    assert site.file.replace("\\", "/") == "pkg/handler.py"
    assert site.line == 4


def test_stdlib_is_not_a_dependency(tmp_path):
    write(tmp_path, "app.py", "import os\nimport json\nimport pathlib\n")
    index = build_index(tmp_path, known_packages={"os", "json"})
    assert not index.sites


def test_modules_outside_the_lockfile_are_dropped_not_guessed(tmp_path):
    write(tmp_path, "app.py", "import myproject_internal\nimport requests\n")
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.for_package("requests")
    assert "myproject_internal" in index.unresolved


def test_test_imports_are_flagged_as_such(tmp_path):
    write(tmp_path, "tests/test_x.py", "import requests\n")
    write(tmp_path, "app/main.py", "import yaml\n")
    index = build_index(tmp_path, known_packages={"requests", "pyyaml"})
    assert index.for_package("requests")[0].in_test
    assert not index.for_package("pyyaml")[0].in_test


def test_vendored_and_virtualenv_directories_are_skipped(tmp_path):
    write(tmp_path, ".venv/lib/site.py", "import requests\n")
    write(tmp_path, "node_modules/x.py", "import requests\n")
    write(tmp_path, "build/y.py", "import requests\n")
    index = build_index(tmp_path, known_packages={"requests"})
    assert not index.for_package("requests")


def test_a_file_that_will_not_parse_does_not_stop_the_scan(tmp_path):
    write(tmp_path, "broken.py", "def (:::\n")
    write(tmp_path, "good.py", "import requests\n")
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.for_package("requests")
    assert index.files_failed == 1


def test_source_roots_include_test_dirs_without_init(tmp_path):
    (tmp_path / "mypkg").mkdir()
    (tmp_path / "mypkg" / "__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("")
    roots = {p.name for p in detect_source_roots(tmp_path)}
    assert "mypkg" in roots and "tests" in roots


# --- the honesty invariant --------------------------------------------------

def _exposed() -> Exposure:
    return Exposure(categories=["auth/session"], confidence=Confidence.CURATED)


def _abandoned() -> Remediation:
    return Remediation(
        repo_archived=True,
        advisories=AdvisoryHistory(total=2, unfixed=1, ids_unfixed=["PYSEC-1"]),
    )


def test_not_being_imported_never_lowers_a_verdict():
    """Dependencies call each other. A package absent from your source can still
    run on every request, so reachability must not be able to downgrade ACT."""
    imported = Package(name="legacy-auth", version="1.0", import_sites=["api/views.py:3"],
                       reachability_checked=True)
    absent = Package(name="legacy-auth", version="1.0", reachability_checked=True)
    unchecked = Package(name="legacy-auth", version="1.0")

    for pkg in (imported, absent, unchecked):
        finding = assess(pkg, _exposed(), _abandoned(), now=NOW)
        assert finding.verdict is Verdict.ACT, pkg.import_sites


def test_an_import_site_is_reported_as_evidence():
    pkg = Package(name="legacy-auth", version="1.0",
                  import_sites=["api/views.py:3"], reachability_checked=True)
    finding = assess(pkg, _exposed(), _abandoned(), now=NOW)
    assert any("api/views.py:3" in r.claim for r in finding.reasons)


def test_test_only_imports_are_described_as_such():
    pkg = Package(name="legacy-auth", version="1.0", import_sites=["tests/test_a.py:1"],
                  imported_in_tests_only=True, reachability_checked=True)
    finding = assess(pkg, _exposed(), _abandoned(), now=NOW)
    assert any("test code" in r.claim for r in finding.reasons)
