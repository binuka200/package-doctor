"""Overlapping source roots must not double-count import sites.

Auto-detection returns each package directory and the project root when
it holds a script, so `core` and `.` both come back for a layout with
`core/__init__.py` and `app.py`, and every file under core was indexed
twice. A user can pass overlapping --src values too. Two rules fix it:
only the outermost roots are walked, and sites are merged by resolved
path and line rather than by their rendered string.
"""

from __future__ import annotations

import json
from pathlib import Path

from package_doctor import cli
from package_doctor.models import Confidence, Exposure, Finding, Remediation, Verdict
from package_doctor.sourcescan import (
    ImportSite,
    build_index,
    detect_source_roots,
    merge_sites,
    prune_nested_roots,
)


def layout(tmp_path: Path) -> Path:
    (tmp_path / "core" / "models").mkdir(parents=True)
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "requirements.txt").write_text("flask==3.1.3\npasslib==1.7.4\n")
    (tmp_path / "core" / "__init__.py").write_text("import flask\n")
    (tmp_path / "core" / "models" / "user.py").write_text("import passlib\nimport flask\n")
    (tmp_path / "app.py").write_text("import flask\n")
    return tmp_path


# --- pruning -----------------------------------------------------------------

def test_a_root_inside_another_is_dropped(tmp_path):
    root = layout(tmp_path)
    assert prune_nested_roots([root / "core", root]) == [root]
    assert prune_nested_roots([root, root / "core"]) == [root]
    assert prune_nested_roots([root / "core", root / "core" / "models"]) == [root / "core"]


def test_disjoint_roots_are_kept_and_repeats_collapsed(tmp_path):
    root = layout(tmp_path)
    assert prune_nested_roots([root / "core", root / "configs", root / "core"]) == [
        root / "core", root / "configs",
    ]


def test_a_file_root_inside_a_directory_root_is_dropped(tmp_path):
    root = layout(tmp_path)
    assert prune_nested_roots([root / "app.py", root]) == [root]
    assert prune_nested_roots([root / "app.py", root / "core"]) == [root / "app.py", root / "core"]


def test_auto_detection_returns_disjoint_roots(tmp_path):
    root = layout(tmp_path)
    roots = detect_source_roots(root)
    assert roots == [root], "core is inside the project root, which holds app.py"


# --- merging -----------------------------------------------------------------

def test_merge_is_by_resolved_path_not_rendered_string():
    a = ImportSite("passlib", "core/models/user.py", 1, False, "/p/core/models/user.py")
    b = ImportSite("passlib", "models/user.py", 1, False, "/p/core/models/user.py")
    c = ImportSite("passlib", "other/user.py", 1, False, "/p/other/user.py")
    merged = merge_sites([[a], [b, c]])
    assert [s.path for s in merged] == ["/p/core/models/user.py", "/p/other/user.py"]
    assert str(merged[0]) == "core/models/user.py:1", "the first rendering wins"


def test_sites_carry_their_resolved_path(tmp_path):
    root = layout(tmp_path)
    index = build_index(root / "core", known_packages={"passlib"}, display_root=root)
    site = index.for_package("passlib")[0]
    assert site.path == str((root / "core" / "models" / "user.py").resolve())


# --- through the CLI ---------------------------------------------------------

def stub(monkeypatch, seen: dict):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            seen.update({p.name: p.import_sites for p in packages})
            return [Finding(package=p, exposure=Exposure(categories=[],
                            confidence=Confidence.CURATED), remediation=Remediation(),
                            verdict=Verdict.OK) for p in packages]

        async def analyze(self, package, now):
            seen[package.name] = package.import_sites
            return Finding(package=package, exposure=Exposure(), remediation=Remediation(),
                           verdict=Verdict.OK)

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_overlapping_src_roots_count_each_site_once(tmp_path, monkeypatch):
    root = layout(tmp_path)
    monkeypatch.chdir(root)
    seen: dict = {}
    stub(monkeypatch, seen)
    cli.main(["scan", "configs/requirements.txt", "--src", ".", "--src", "core", "--no-cache"])
    assert seen["passlib"] == ["core/models/user.py:1"]
    assert seen["flask"] == ["app.py:1", "core/__init__.py:1", "core/models/user.py:2"]


def test_auto_detected_roots_count_each_site_once(tmp_path, monkeypatch):
    root = layout(tmp_path)
    monkeypatch.chdir(root)
    seen: dict = {}
    stub(monkeypatch, seen)
    cli.main(["scan", "configs/requirements.txt", "--src", "core", "--src", ".", "--no-cache"])
    assert seen["passlib"] == ["core/models/user.py:1"]


def test_explain_no_longer_lists_a_site_twice(tmp_path, monkeypatch, capsys):
    root = layout(tmp_path)
    (root / "requirements.txt").write_text("flask==3.1.3\npasslib==1.7.4\n")
    seen: dict = {}
    stub(monkeypatch, seen)
    cli.main(["explain", "passlib", "--path", str(root), "--no-cache", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["reachability"]["sites"] == ["core/models/user.py:1"]


def test_a_missing_src_is_still_reported_and_the_rest_scanned(tmp_path, monkeypatch, capsys):
    root = layout(tmp_path)
    monkeypatch.chdir(root)
    seen: dict = {}
    stub(monkeypatch, seen)
    cli.main(["scan", "configs/requirements.txt", "--src", "nope", "--src", "core", "--no-cache"])
    assert "No such file or directory, skipping" in capsys.readouterr().out
    assert seen["passlib"] == ["core/models/user.py:1"]
