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
        verdict=Verdict.REPLACE,
        reasons=[Evidence("[blink]LOOK AT ME[/blink] and \x1b[31mred\x1b[0m")],
    )
    render(console, [finding], sources=["requirements.txt"])
    out = buf.getvalue()
    assert "[blink]LOOK AT ME[/blink]" in out
    # Markup being inert is not enough: rich passes a raw ESC straight through
    # to the terminal, so the sequence has to be stripped, not just not parsed.
    assert "\x1b" not in out
    assert "red" in out, "the words around a stripped sequence must survive"


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


# --- terminal escape sequences from any untrusted field are stripped ---------

def _render_one(finding):
    """Render to a plain console, so any escape in the output is one that
    came from the data and not from rich's own styling."""
    from package_doctor.report import render
    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=False, color_system=None)
    render(console, [finding], sources=["uv.lock"])
    return buf.getvalue()


def test_a_lockfile_version_cannot_carry_an_escape_sequence():
    """The version column is copied verbatim from the lockfile, which the user
    did not write. An OSC 8 sequence there would turn the row into a hyperlink
    to wherever the lockfile's author chose."""
    from package_doctor.models import (
        Confidence,
        Exposure,
        Finding,
        Package,
        Remediation,
        Verdict,
    )
    finding = Finding(
        package=Package(name="demo", version="1.0\x1b]8;;https://evil.invalid\x1b\\"),
        exposure=Exposure(categories=["crypto"], confidence=Confidence.CURATED),
        remediation=Remediation(),
        verdict=Verdict.MITIGATE,
    )
    out = _render_one(finding)
    assert "demo  1.0" in out, "the version is kept"
    assert "\x1b" not in out, "the sequence is not"
    # The OSC payload is the hidden link target, not display text, so it goes
    # with the sequence rather than being left behind as a bare URL.
    assert "evil.invalid" not in out


def test_explain_strips_escapes_from_paths_urls_and_ids():
    """Import sites are file names from the scanned tree; repo URLs and
    advisory ids come from third-party APIs. None of them gets to talk to the
    terminal directly."""
    from package_doctor.models import (
        AdvisoryHistory,
        Confidence,
        Evidence,
        Exposure,
        Finding,
        Package,
        Remediation,
        Verdict,
    )
    from package_doctor.report import render_explain

    rem = Remediation(
        repo_url="https://github.com/x/y\x1b[2J",
        advisories=AdvisoryHistory(total=1, unfixed=1, ids_unfixed=["GHSA-\x1b[31mxx"]),
        gaps=["lookup failed: \x07\x1b[0m"],
    )
    finding = Finding(
        package=Package(
            name="demo", version="1.0", import_sites=["app/\x1b[1;31mevil.py:3"],
            reachability_checked=True,
        ),
        exposure=Exposure(categories=["crypto"], confidence=Confidence.CURATED),
        remediation=rem,
        verdict=Verdict.REPLACE,
        reasons=[Evidence("claim \u202eevil", "https://osv.dev/\x1b]8;;x\x1b\\")],
    )
    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=False, color_system=None)
    render_explain(console, finding)
    out = buf.getvalue()
    assert "\x1b[2J" not in out and "\x1b]8" not in out and "\x1b[1;31m" not in out
    assert "\x07" not in out
    assert "\u202e" not in out, "bidi overrides are formatting characters and go too"
    assert "evil.py:3" in out and "GHSA-xx" in out and "github.com/x/y" in out


def test_clean_keeps_ordinary_unicode():
    from package_doctor.report import clean
    assert clean("café — naïve ✓ 日本") == "café — naïve ✓ 日本"
    assert clean("a\x1b[0mb\x00c\u200bd") == "abcd"
    assert clean("x\x1b]8;;https://evil.invalid\x1b\\link\x1b]8;;\x1b\\y") == "xlinky"
    assert clean("bare\x1bescape") == "bareescape", "an unrecognised ESC still goes"


# --- a scanned tree must not contain anything that blocks or floods a read --

@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX only")
def test_a_fifo_named_like_a_source_file_is_not_opened(tmp_path):
    """open() on a FIFO blocks until a writer appears. A checkout can contain
    one, and it reports a size of zero, so a size check does not see it."""
    import os

    from package_doctor.sourcescan import build_index

    os.mkfifo(tmp_path / "evil.py")
    (tmp_path / "ok.py").write_text("import requests\n", encoding="utf-8")
    # If the FIFO is opened this test hangs rather than fails; a hang is the
    # bug, and the suite's absence of a timeout is deliberate elsewhere.
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.for_package("requests")
    assert index.files_failed == 1


def test_a_symlink_to_a_special_file_is_not_read(tmp_path):
    """/dev/zero has a size of zero and reads forever."""
    import os

    from package_doctor.sourcescan import build_index

    target = "/dev/zero" if os.path.exists("/dev/zero") else "NUL"
    try:
        (tmp_path / "zero.py").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    if not (tmp_path / "zero.py").exists():
        pytest.skip("no special file to point at")
    (tmp_path / "ok.py").write_text("import requests\n", encoding="utf-8")
    index = build_index(tmp_path, known_packages={"requests"})
    assert index.for_package("requests")
    assert index.files_failed == 1


def test_the_source_read_is_bounded_not_just_size_checked(tmp_path, monkeypatch):
    """The cap must hold even if the size seen by stat() is a lie - a file
    replaced between the check and the read, for instance."""
    from pathlib import Path

    from package_doctor.sourcescan import build_index

    big = tmp_path / "big.py"
    big.write_text("import yaml\n" + "#" * 100, encoding="utf-8")
    real_stat = Path.stat

    def lying_stat(self, *a, **kw):
        result = real_stat(self, *a, **kw)
        if self.name == "big.py":
            import os
            return os.stat_result((result.st_mode, 0, 0, 0, 0, 0, 1, 0, 0, 0))
        return result

    monkeypatch.setattr(Path, "stat", lying_stat)
    index = build_index(tmp_path, known_packages={"pyyaml"}, max_bytes=50)
    assert index.files_too_large == 1
    assert not index.for_package("pyyaml")


# --- a dependency file must not be able to exhaust or crash the parser -----

def test_an_oversized_lockfile_is_refused_and_reported(tmp_path):
    """Lockfiles are read whole into a parser. Without a cap, a checkout can
    hand the scanner a multi-gigabyte one, or a symlink to one."""
    write(tmp_path, "uv.lock", '[[package]]\nname = "requests"\nversion = "2.32.3"\n' * 40)
    write(tmp_path, "requirements.txt", "urllib3==2.0.7\n")
    deps = collect_dependencies(discover_manifests(tmp_path), max_bytes=200)
    assert set(deps.versions) == {"urllib3"}, "the small file is still read"
    assert [p.name for p in deps.refused] == ["uv.lock"]
    assert [p.name for p in deps.sources] == ["requirements.txt"]


def test_a_refused_lockfile_is_reported_to_the_user(tmp_path, monkeypatch, capsys):
    """A skipped lockfile must not look like an empty one."""
    from package_doctor import cli
    from package_doctor.parsers import discovery

    write(tmp_path, "requirements.txt", "urllib3==2.0.7\n")
    (tmp_path / "uv.lock").write_text("x" * 10, encoding="utf-8")
    monkeypatch.setattr(
        cli, "collect_dependencies",
        lambda paths, **kw: discovery.collect_dependencies(paths, max_bytes=5, **kw),
    )

    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return []

    monkeypatch.setattr(cli, "Analyzer", Stub)
    cli.main(["scan", str(tmp_path), "--no-reachability", "--no-cache"])
    out = capsys.readouterr().out
    assert "Not read:" in out and "uv.lock" in out


# Explicit ids: pytest puts the test id into PYTEST_CURRENT_TEST, and a
# twenty-thousand-bracket parameter value pushed that past the 32,767-character
# ceiling Windows puts on an environment variable.
@pytest.mark.parametrize("name, body", [
    ("uv.lock", "a = " + "[" * 20000),
    ("poetry.lock", "a = " + "{b=" * 20000),
    ("pyproject.toml", "[project]\ndependencies = " + "[" * 20000),
    ("Pipfile", "[packages]\nx = " + "{a=" * 20000),
    ("Pipfile.lock", "[" * 200000),
], ids=["uv-arrays", "poetry-tables", "pyproject-arrays", "pipfile-tables", "pipfile-lock-json"])
def test_pathologically_nested_dependency_files_are_malformed_not_fatal(tmp_path, name, body):
    """tomllib recurses on nested values and raises RecursionError, which is
    not a TOMLDecodeError. It has to end as "malformed", not as a traceback."""
    write(tmp_path, name, body)
    write(tmp_path, "requirements.txt", "urllib3==2.0.7\n")
    deps = collect_dependencies(discover_manifests(tmp_path))
    assert set(deps.versions) == {"urllib3"}
