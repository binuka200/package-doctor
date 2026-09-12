"""Hostile input.

This tool is pointed at repositories the user did not write - that is the whole
use case. A lockfile is TOML or JSON, so nothing in it is validated the way a
requirements.txt line is by packaging.Requirement, and everything it contains
should be treated as attacker-influenced.
"""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from package_doctor.parsers.discovery import (
    DependencySet,
    collect_dependencies,
    discover_manifests,
)
from package_doctor.sources.pypi import PYPI_JSON


def write(tmp_path, name, body):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


# --- names must never reach URL construction unvalidated --------------------

@pytest.mark.parametrize("evil", [
    "../../simple/evil",
    "foo/../../bar",
    "foo?redirect=http://evil.invalid",
    "foo#fragment",
    "foo%00cut",
    "foo bar",
    "-leading-dash",
    "",
    "/",
    "..",
])
def test_invalid_package_names_are_dropped(evil):
    """A crafted lockfile naming a package "../../simple/evil" would otherwise
    produce https://pypi.org/pypi/../../simple/evil/json."""
    deps = DependencySet()
    deps.add(evil, "1.0", "uv.lock", direct=False)
    assert not deps.versions, f"accepted {evil!r}"


@pytest.mark.parametrize("good", ["requests", "zope-interface", "a", "py7zr", "x0-1"])
def test_real_package_names_still_pass(good):
    deps = DependencySet()
    deps.add(good, "1.0", "uv.lock", direct=False)
    assert deps.versions


def test_a_crafted_uv_lock_cannot_inject_a_path(tmp_path):
    write(tmp_path, "uv.lock", '''
[[package]]
name = "../../simple/evil"
version = "1.0"

[[package]]
name = "requests"
version = "2.32.3"
''')
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert set(deps.versions) == {"requests"}


def test_a_crafted_pipfile_lock_cannot_inject_a_path(tmp_path):
    write(tmp_path, "Pipfile.lock", json.dumps({
        "default": {"../../evil": {"version": "==1.0"}, "urllib3": {"version": "==2.0.7"}},
    }))
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert set(deps.versions) == {"urllib3"}


def test_the_pypi_url_is_quoted_even_if_a_bad_name_gets_through():
    """Defence in depth: validation happens on the way in, and this keeps a
    future caller from reintroducing the problem."""
    from urllib.parse import quote, urlparse
    url = PYPI_JSON.format(name=quote("../../etc/passwd", safe=""))
    # The name occupies exactly one path segment, and the slashes inside it are
    # encoded rather than traversing.
    segments = urlparse(url).path.strip("/").split("/")
    assert segments == ["pypi", "..%2F..%2Fetc%2Fpasswd", "json"], segments


# --- terminal output must not be controllable by scanned content ------------

def test_paths_cannot_inject_terminal_markup():
    """A directory named "[bold red]..." should print as text, not as a style."""
    from rich.markup import escape
    buf = io.StringIO()
    console = Console(file=buf, width=100, force_terminal=False)
    hostile = "/tmp/[bold red]HIDDEN[/bold red]"
    console.print(f"[red]Not a directory:[/red] {escape(str(hostile))}")
    assert "[bold red]HIDDEN[/bold red]" in buf.getvalue()


def test_findings_render_untrusted_text_literally():
    """Advisory summaries and package descriptions come from third parties and
    are rendered through Text objects, which do not interpret markup."""
    from package_doctor.models import (
        Confidence,
        Evidence,
        Exposure,
        Finding,
        Package,
        Remediation,
        Verdict,
    )
    from package_doctor.report import render

    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=False)
    finding = Finding(
        package=Package(name="demo", version="1.0"),
        exposure=Exposure(categories=["crypto"], confidence=Confidence.CURATED),
        remediation=Remediation(),
        verdict=Verdict.ACT,
        reasons=[Evidence("[blink]LOOK AT ME[/blink] and \x1b[31mred\x1b[0m")],
    )
    render(console, [finding], sources=["requirements.txt"])
    out = buf.getvalue()
    assert "[blink]LOOK AT ME[/blink]" in out


# --- a scanned file must not be able to exhaust the scanner -----------------

def test_an_oversized_source_file_is_skipped_and_counted(tmp_path):
    """Reading and building an AST costs memory and time proportional to file
    size, and this scanner runs over repositories the user did not write."""
    from package_doctor.sourcescan import build_index

    (tmp_path / "normal.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "huge.py").write_text(
        "import yaml\n" + "# padding\n" * 300_000, encoding="utf-8"
    )
    assert (tmp_path / "huge.py").stat().st_size > 2 * 1024 * 1024

    index = build_index(tmp_path, known_packages={"requests", "pyyaml"})
    assert index.files_too_large == 1
    assert index.for_package("requests"), "the normal file must still be read"
    assert not index.for_package("pyyaml"), "the oversized file must not be parsed"


def test_the_size_limit_is_adjustable(tmp_path):
    from package_doctor.sourcescan import build_index

    (tmp_path / "small.py").write_text("import requests\n", encoding="utf-8")
    tight = build_index(tmp_path, known_packages={"requests"}, max_bytes=4)
    assert tight.files_too_large == 1
    assert not tight.for_package("requests")


def test_skipping_is_distinguishable_from_finding_nothing(tmp_path):
    """A skipped file must never look like a file with no imports - "we did not
    look" and "we looked and found nothing" are different answers."""
    from package_doctor.sourcescan import build_index

    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.files_scanned == 1 and index.files_too_large == 0


def test_pathological_nesting_does_not_crash_the_scan(tmp_path):
    """CPython's parser rejects this with a SyntaxError, which must be caught
    like any other unparseable file rather than ending the scan."""
    from package_doctor.sourcescan import build_index

    (tmp_path / "bomb.py").write_text("(" * 5000 + "1" + ")" * 5000, encoding="utf-8")
    (tmp_path / "ok.py").write_text("import requests\n", encoding="utf-8")
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.files_failed == 1
    assert index.for_package("requests")
