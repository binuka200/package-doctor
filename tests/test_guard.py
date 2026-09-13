"""The guardrail: decisions at install time, and the hook that delivers them.

Three commitments. Provenance facts - not on PyPI, brand new, one edit from
a popular name - can block, because they are facts. The scanner's verdict
maps to a decision without a new rule: act blocks, watch warns. And the hook
fails open: anything that is not a decision about a package lets the
install through, because a guardrail that stops work on somebody else's
outage is the first thing a team removes.
"""

from __future__ import annotations

import datetime as dt
import io
import json

import pytest

from package_doctor import cli
from package_doctor.guard import (
    BLOCK,
    OK,
    UNCHECKED,
    WARN,
    decide,
    near_miss,
    one_edit_apart,
    parse_install_command,
    parse_requirement,
)
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
POPULAR = ("requests", "pillow", "numpy", "django", "flask", "boto3", "attrs", "six")


# --- one edit apart ---------------------------------------------------------

@pytest.mark.parametrize("a, b", [
    ("reqeusts", "requests"),   # transposition
    ("request", "requests"),    # deletion
    ("requestss", "requests"),  # insertion
    ("requezts", "requests"),   # substitution
])
def test_one_edit_apart_covers_the_four_typo_shapes(a, b):
    assert one_edit_apart(a, b) and one_edit_apart(b, a)


@pytest.mark.parametrize("a, b", [
    ("requests", "requests"), ("reqests2", "requests"), ("django", "flask"), ("ab", "ba1"),
])
def test_one_edit_apart_rejects_same_and_further(a, b):
    assert not one_edit_apart(a, b)


def test_near_miss_names_the_popular_package():
    assert near_miss("reqeusts", POPULAR) == "requests"
    assert near_miss("Pillow_", POPULAR) == "pillow"


def test_near_miss_ignores_popular_names_and_very_short_ones():
    assert near_miss("requests", POPULAR) is None, "the real thing is not a miss"
    assert near_miss("attrs", POPULAR) is None
    assert near_miss("sixx", POPULAR) is None, "four characters: everything is one edit away"
    assert near_miss("httpx", POPULAR) is None


# --- reading install commands ----------------------------------------------

@pytest.mark.parametrize("command, expected", [
    ("pip install requests", ["requests"]),
    ("pip3 install 'pillow==10.0.0' numpy", ["pillow==10.0.0", "numpy"]),
    ("python -m pip install --upgrade requests", ["requests"]),
    ("python3.12 -m pip install -q requests", ["requests"]),
    ("uv add httpx rich", ["httpx", "rich"]),
    ("uv add --dev pytest", ["pytest"]),
    ("uv pip install -r requirements.txt", []),
    ("poetry add django", ["django"]),
    ("pipenv install flask", ["flask"]),
    ("pdm add typer", ["typer"]),
    ("pipx install ruff", ["ruff"]),
    ("pipx inject myapp requests", ["requests"]),
    ("pip install -e . && pip install requests", ["requests"]),
    ("cd app; pip install ./vendor/pkg.whl https://x/y.tar.gz git+https://g/r", []),
    ("pip install -i https://mirror/simple requests", ["requests"]),
    ("pip install --index-url=https://mirror/simple requests", ["requests"]),
    ("pip install 'fastapi[all]>=0.100'", ["fastapi[all]>=0.100"]),
    ("pip install -t /tmp/target requests", ["requests"]),
    ("ls -la && pytest", []),
    ("pip freeze", []),
    ("pip install", []),
    ("echo 'pip install requests'", []),
])
def test_install_commands_yield_the_names_they_would_add(command, expected):
    assert parse_install_command(command) == expected


def test_a_command_shlex_cannot_read_installs_nothing():
    assert parse_install_command("pip install 'unterminated") == []


def test_parse_requirement_splits_pin_from_range():
    assert parse_requirement("pillow==10.0.0") == ("pillow", "10.0.0", None)
    assert parse_requirement("django<5") == ("django", None, "<5")
    assert parse_requirement("requests") == ("requests", None, None)


# --- the decision -----------------------------------------------------------

def finding(
    name: str = "thing",
    verdict: Verdict = Verdict.OK,
    *,
    error: str | None = None,
    first: dt.datetime | None = NOW - dt.timedelta(days=900),
    exposed: bool = False,
    reasons: list[str] = (),
) -> Finding:
    return Finding(
        package=Package(name=name, version="1.0"),
        exposure=Exposure(
            categories=["auth/session"] if exposed else [],
            confidence=Confidence.CURATED,
            note=None if exposed else "reviewed: not at a trust boundary",
        ),
        remediation=Remediation(first_release=first, last_release=first),
        verdict=verdict,
        reasons=[Evidence(r) for r in reasons],
        error=error,
    )


def test_not_on_pypi_blocks_and_names_a_near_miss():
    d = decide(finding("reqeusts", Verdict.UNKNOWN, error="not found on PyPI", first=None),
               now=NOW, popular=POPULAR)
    assert d.level == BLOCK
    assert d.provenance.found is False
    assert any("not on PyPI" in r for r in d.reasons)
    assert any("requests" in r for r in d.reasons)


def test_a_brand_new_package_blocks():
    d = decide(finding("fresh-thing", first=NOW - dt.timedelta(days=3)), now=NOW, popular=POPULAR)
    assert d.level == BLOCK
    assert d.provenance.days_since_first_release == 3
    assert "3 days ago" in d.reasons[0]


def test_the_new_window_is_configurable():
    f = finding("fresh-thing", first=NOW - dt.timedelta(days=40))
    assert decide(f, now=NOW, popular=POPULAR).level == OK
    assert decide(f, now=NOW, popular=POPULAR, new_days=60).level == BLOCK


def test_a_near_miss_alone_warns():
    d = decide(finding("reqeusts"), now=NOW, popular=POPULAR)
    assert d.level == WARN
    assert d.provenance.near_miss == "requests"


def test_act_blocks_with_the_scanner_reasons():
    d = decide(finding("legacy-auth", Verdict.ACT, exposed=True,
                       reasons=["repository is archived", "2 advisories with no published fix"]),
               now=NOW, popular=POPULAR)
    assert d.level == BLOCK
    assert "repository is archived" in d.reasons[0]


def test_watch_warns_and_low_unknown_ok_pass():
    assert decide(finding("pyjwt", Verdict.WATCH, exposed=True,
                          reasons=["7 of 8 past advisories fixed at or before disclosure"]),
                  now=NOW, popular=POPULAR).level == WARN
    for verdict in (Verdict.LOW, Verdict.UNKNOWN, Verdict.OK):
        assert decide(finding("thing", verdict), now=NOW, popular=POPULAR).level == OK


def test_a_failed_lookup_is_unchecked_and_allowed():
    """An outage elsewhere is not evidence about the package."""
    d = decide(finding("thing", Verdict.UNKNOWN, error="lookup failed: boom", first=None),
               now=NOW, popular=POPULAR)
    assert d.level == UNCHECKED
    assert d.provenance.found is None
    d = decide(finding("thing", Verdict.UNKNOWN, first=None), now=NOW, popular=POPULAR,
               degraded=True)
    assert d.level == UNCHECKED


def test_provenance_never_touches_the_verdict():
    f = finding("fresh-thing", Verdict.OK, first=NOW - dt.timedelta(days=1))
    decide(f, now=NOW, popular=POPULAR)
    assert f.verdict is Verdict.OK


# --- the check command ------------------------------------------------------

def stub(monkeypatch, findings):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            by_name = {f.package.name: f for f in findings}
            return [by_name[p.name] for p in packages]

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_check_prints_one_decision_per_package_and_exits_on_block(monkeypatch, capsys):
    stub(monkeypatch, [
        finding("legacy-auth", Verdict.ACT, exposed=True, reasons=["repository is archived"]),
        finding("six"),
    ])
    code = cli.main(["check", "legacy-auth", "six", "--no-cache"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_FINDINGS
    assert "BLOCK" in out and "legacy-auth" in out and "repository is archived" in out
    assert "OK" in out and "six" in out


def test_check_fail_on_never_and_warn(monkeypatch):
    stub(monkeypatch, [finding("pyjwt", Verdict.WATCH, exposed=True, reasons=["x"])])
    assert cli.main(["check", "pyjwt", "--no-cache"]) == cli.EXIT_OK
    assert cli.main(["check", "pyjwt", "--no-cache", "--fail-on", "warn"]) == cli.EXIT_FINDINGS
    stub(monkeypatch, [finding("legacy-auth", Verdict.ACT, exposed=True, reasons=["x"])])
    assert cli.main(["check", "legacy-auth", "--no-cache", "--fail-on", "never"]) == cli.EXIT_OK


def test_check_json_carries_level_reasons_and_provenance(monkeypatch, capsys):
    stub(monkeypatch, [finding("fresh-thing", first=NOW - dt.timedelta(days=2))])
    cli.main(["check", "fresh-thing", "--json", "--no-cache"])
    payload = json.loads(capsys.readouterr().out)
    row = payload["checks"][0]
    assert row["level"] == "block"
    assert row["provenance"]["found"] is True
    assert row["provenance"]["near_miss"] is None
    assert "first published" in row["reasons"][0]


def test_check_rejects_a_malformed_requirement(monkeypatch, capsys):
    stub(monkeypatch, [])
    assert cli.main(["check", "not a requirement!!", "--no-cache"]) == cli.EXIT_USAGE
    assert "Not a requirement" in capsys.readouterr().out


# --- the Claude Code hook ---------------------------------------------------

def hook_event(command: str, tool: str = "Bash") -> str:
    return json.dumps({
        "session_id": "s", "cwd": "/tmp", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_input": {"command": command},
    })


def run_hook(monkeypatch, stdin: str, *extra: str) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(["hook", "claude-code", "--no-cache", *extra])


def test_hook_blocks_with_exit_2_and_reasons_on_stderr(monkeypatch, capsys):
    stub(monkeypatch, [finding("legacy-auth", Verdict.ACT, exposed=True,
                               reasons=["repository is archived"])])
    code = run_hook(monkeypatch, hook_event("pip install legacy-auth"))
    out, err = capsys.readouterr()
    assert code == 2
    assert "blocked" in err and "legacy-auth" in err and "repository is archived" in err
    assert "alternative" in err, "the model is told what to do instead"
    assert out == "", "exit 2 is the decision; no JSON needed"


def test_hook_warns_as_context_without_granting_permission(monkeypatch, capsys):
    stub(monkeypatch, [finding("pyjwt", Verdict.WATCH, exposed=True, reasons=["trust boundary"])])
    code = run_hook(monkeypatch, hook_event("uv add pyjwt"))
    out, err = capsys.readouterr()
    assert code == 0
    payload = json.loads(out)
    assert "WARN pyjwt" in payload["systemMessage"]
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "permissionDecision" not in payload["hookSpecificOutput"], (
        "a warning must never become an automatic allow"
    )


def test_hook_is_silent_when_everything_is_fine(monkeypatch, capsys):
    stub(monkeypatch, [finding("six")])
    assert run_hook(monkeypatch, hook_event("pip install six")) == 0
    assert capsys.readouterr().out == ""


def test_hook_ignores_calls_that_install_nothing(monkeypatch, capsys):
    called = []

    class Stub:
        def __init__(self, *a, **kw):
            called.append(1)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    assert run_hook(monkeypatch, hook_event("pytest -q")) == 0
    assert run_hook(monkeypatch, hook_event("pip install x", tool="Edit")) == 0
    assert run_hook(monkeypatch, "not json") == 0
    assert run_hook(monkeypatch, "") == 0
    assert run_hook(monkeypatch, json.dumps({"tool_name": "Bash", "tool_input": {}})) == 0
    assert not called
    assert capsys.readouterr().out == ""


def test_hook_fails_open_when_the_lookup_explodes(monkeypatch, capsys):
    class Boom:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            raise RuntimeError("upstream exploded")

    monkeypatch.setattr(cli, "Analyzer", Boom)
    code = run_hook(monkeypatch, hook_event("pip install requests"))
    out, _ = capsys.readouterr()
    assert code == 0
    assert "allowed unchecked" in json.loads(out)["systemMessage"]


def test_hook_can_be_told_to_block_on_warnings(monkeypatch, capsys):
    stub(monkeypatch, [finding("pyjwt", Verdict.WATCH, exposed=True, reasons=["x"])])
    assert run_hook(monkeypatch, hook_event("pip install pyjwt"), "--warn-blocks") == 2


def test_hook_blocks_an_invented_name(monkeypatch, capsys):
    stub(monkeypatch, [finding("reqeusts", Verdict.UNKNOWN, error="not found on PyPI",
                               first=None)])
    code = run_hook(monkeypatch, hook_event("pip install reqeusts"))
    _, err = capsys.readouterr()
    assert code == 2 and "not on PyPI" in err
