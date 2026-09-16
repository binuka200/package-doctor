"""Accepted risks: the file that keeps a known finding from failing every build.

The rules under test are the ones that make suppression safe to offer: every
entry has a reason and an expiry, an expired entry stops suppressing and says
so, and an accepted finding is still in the report. A suppression file that
could hide a finding for good would undo the rest of the tool.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from rich.console import Console

from package_doctor import cli
from package_doctor.accept import ConfigError, apply_acceptances, load_acceptances
from package_doctor.models import (
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.report import render, render_markdown, to_dict

NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)


def finding(name: str, verdict: Verdict = Verdict.REPLACE, version: str | None = "1.0") -> Finding:
    return Finding(
        package=Package(name=name, version=version),
        exposure=Exposure(categories=["auth/session"], confidence=Confidence.CURATED),
        remediation=Remediation(),
        verdict=verdict,
        reasons=[Evidence("repository is archived")],
    )


def write(root: Path, body: str, name: str = "package-doctor.toml") -> Path:
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


GOOD = '''
[[accept]]
package = "Legacy_Auth"
reason = "Replacement scheduled, PROJ-123"
until = 2099-01-01
'''


# --- reading the file -------------------------------------------------------

def test_no_file_means_no_acceptances(tmp_path):
    loaded = load_acceptances(tmp_path)
    assert loaded.entries == [] and loaded.path is None


def test_entries_are_read_and_names_normalised(tmp_path):
    write(tmp_path, GOOD)
    loaded = load_acceptances(tmp_path)
    assert [e.package for e in loaded.entries] == ["legacy-auth"]
    assert loaded.entries[0].until == dt.date(2099, 1, 1)
    assert loaded.entries[0].source == "package-doctor.toml"


def test_pyproject_tool_table_is_read_when_there_is_no_dedicated_file(tmp_path):
    write(tmp_path, '[tool.package-doctor]\n[[tool.package-doctor.accept]]\n'
                    'package = "a"\nreason = "r"\nuntil = 2099-01-01\n', "pyproject.toml")
    loaded = load_acceptances(tmp_path)
    assert [e.package for e in loaded.entries] == ["a"]
    assert loaded.path == tmp_path / "pyproject.toml"


def test_the_dedicated_file_wins_over_pyproject(tmp_path):
    write(tmp_path, '[[tool.package-doctor.accept]]\npackage = "from-pyproject"\n'
                    'reason = "r"\nuntil = 2099-01-01\n', "pyproject.toml")
    write(tmp_path, GOOD)
    assert [e.package for e in load_acceptances(tmp_path).entries] == ["legacy-auth"]


def test_an_explicit_path_is_used_and_must_exist(tmp_path):
    custom = write(tmp_path, GOOD, "risks.toml")
    assert load_acceptances(tmp_path / "elsewhere", custom).entries
    with pytest.raises(ConfigError, match="not found"):
        load_acceptances(tmp_path, tmp_path / "missing.toml")


@pytest.mark.parametrize(
    "body, complaint",
    [
        ('[[accept]]\nreason = "r"\nuntil = 2099-01-01\n', "needs a 'package'"),
        ('[[accept]]\npackage = "a"\nuntil = 2099-01-01\n', "needs a 'reason'"),
        ('[[accept]]\npackage = "a"\nreason = "  "\nuntil = 2099-01-01\n', "needs a 'reason'"),
        ('[[accept]]\npackage = "a"\nreason = "r"\n', "needs an 'until'"),
        ('[[accept]]\npackage = "a"\nreason = "r"\nuntil = "someday"\n', "needs an 'until'"),
        ('[[accept]]\npackage = "a"\nreason = "r"\nuntil = 2099-01-01\nversion = 2\n',
         "'version' must be a string"),
        ('[[accept]]\npackage = "a"\nreason = "r"\nuntil = 2099-01-01\nforever = true\n',
         "unknown key"),
        ('accept = "a"\n', "array of tables"),
        ('accept = ["a"]\n', "must be a table"),
        ('[[accept\n', "not valid TOML"),
    ],
)
def test_a_malformed_entry_is_refused_not_ignored(tmp_path, body, complaint):
    """An entry that silently failed to apply would fail a build for no
    visible reason; one that silently applied too widely would hide risk.
    Either way the answer is to stop and say what is wrong."""
    write(tmp_path, body)
    with pytest.raises(ConfigError, match=complaint):
        load_acceptances(tmp_path)


def test_a_datetime_until_is_accepted_as_its_date(tmp_path):
    write(tmp_path, '[[accept]]\npackage = "a"\nreason = "r"\nuntil = 2099-01-01T12:00:00Z\n')
    assert load_acceptances(tmp_path).entries[0].until == dt.date(2099, 1, 1)


# --- applying them ----------------------------------------------------------

def test_an_unexpired_acceptance_suppresses_the_finding(tmp_path):
    write(tmp_path, GOOD)
    f = finding("legacy-auth")
    notes = apply_acceptances([f], load_acceptances(tmp_path), NOW)
    assert f.suppressed and not f.acceptance_expired
    assert f.verdict is Verdict.REPLACE, "the verdict is a fact about the package, unchanged"
    assert notes == []


def test_an_expired_acceptance_stops_suppressing(tmp_path):
    write(tmp_path, '[[accept]]\npackage = "legacy-auth"\nreason = "r"\nuntil = 2026-09-12\n')
    f = finding("legacy-auth")
    apply_acceptances([f], load_acceptances(tmp_path), NOW)
    assert f.accepted is not None and f.acceptance_expired
    assert not f.suppressed


def test_an_acceptance_expiring_today_still_holds(tmp_path):
    write(tmp_path, '[[accept]]\npackage = "legacy-auth"\nreason = "r"\nuntil = 2026-09-13\n')
    f = finding("legacy-auth")
    apply_acceptances([f], load_acceptances(tmp_path), NOW)
    assert f.suppressed


def test_a_version_bound_acceptance_lapses_on_upgrade(tmp_path):
    write(tmp_path, '[[accept]]\npackage = "legacy-auth"\nreason = "r"\n'
                    'until = 2099-01-01\nversion = "1.0"\n')
    same, upgraded = finding("legacy-auth", version="1.0"), finding("legacy-auth", version="1.1")
    assert apply_acceptances([same], load_acceptances(tmp_path), NOW) == []
    assert same.suppressed
    notes = apply_acceptances([upgraded], load_acceptances(tmp_path), NOW)
    assert not upgraded.suppressed and upgraded.accepted is None
    assert any("is for version 1.0" in n and "1.1 is pinned" in n for n in notes)


def test_stale_entries_are_reported_not_silently_ignored(tmp_path):
    write(tmp_path, GOOD + '\n[[accept]]\npackage = "fine"\nreason = "r"\nuntil = 2099-01-01\n')
    notes = apply_acceptances([finding("fine", Verdict.OK)], load_acceptances(tmp_path), NOW)
    assert any("legacy-auth matched no scanned package" in n for n in notes)
    assert any("fine is not needed" in n for n in notes)


def test_a_duplicate_entry_applies_once_and_says_so(tmp_path):
    write(tmp_path, GOOD + GOOD)
    f = finding("legacy-auth")
    notes = apply_acceptances([f], load_acceptances(tmp_path), NOW)
    assert f.suppressed
    assert any("listed twice" in n for n in notes)


# --- what the user sees -----------------------------------------------------

def test_accepted_findings_stay_in_the_report(capsys):
    """Suppressed from the exit code, never from the reader."""
    f = finding("legacy-auth")
    from package_doctor.models import Acceptance
    f.accepted = Acceptance("legacy-auth", "PROJ-123 in flight", dt.date(2099, 1, 1), source="x")
    render(Console(width=100, force_terminal=False), [f], sources=["r.txt"], now=NOW)
    out = capsys.readouterr().out
    assert "ACCEPTED RISK" in out
    assert "legacy-auth" in out and "PROJ-123 in flight" in out
    assert "until 2099-01-01" in out
    assert "NO ONE HOME" not in out, "moved out of the act section"
    assert "1 accepted" in out
    md = render_markdown([f], sources=["r.txt"], now=NOW)
    assert "Accepted Risk" in md and "PROJ-123 in flight" in md


def test_an_expired_acceptance_is_shown_in_its_verdict_section_with_the_reason(capsys):
    from package_doctor.models import Acceptance
    f = finding("legacy-auth")
    f.accepted = Acceptance("legacy-auth", "PROJ-123", dt.date(2026, 1, 1), source="x")
    f.acceptance_expired = True
    render(Console(width=100, force_terminal=False), [f], sources=["r.txt"], now=NOW)
    out = capsys.readouterr().out
    assert "REPLACE" in out and "expired 2026-01-01" in out and "PROJ-123" in out
    assert "ACCEPTED RISK" not in out


def test_json_carries_the_acceptance_and_a_suppressed_flag():
    from package_doctor.models import Acceptance
    f = finding("legacy-auth")
    f.accepted = Acceptance("legacy-auth", "r", dt.date(2099, 1, 1), version="1.0", source="x")
    payload = to_dict([f, finding("other")], [], NOW)
    row = payload["findings"][0]["accepted"]
    assert row == {
        "reason": "r", "until": "2099-01-01", "version": "1.0", "source": "x",
        "expired": False, "suppressed": True,
    }
    assert payload["findings"][1]["accepted"] is None
    assert payload["accepted"] == 1
    assert payload["counts"] == {"replace": 2}, "counts are by verdict; acceptance is separate"


# --- the CI contract --------------------------------------------------------

def stub(monkeypatch, findings):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return findings

        async def analyze(self, package, now):
            return findings[0]

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_an_accepted_finding_does_not_fail_the_build(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("legacy-auth==1.0\n", encoding="utf-8")
    stub(monkeypatch, [finding("legacy-auth")])
    assert cli.main(["scan", str(tmp_path), "--no-reachability"]) == cli.EXIT_FINDINGS
    write(tmp_path, GOOD)
    assert cli.main(["scan", str(tmp_path), "--no-reachability"]) == cli.EXIT_OK


def test_an_expired_acceptance_fails_the_build_again(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("legacy-auth==1.0\n", encoding="utf-8")
    write(tmp_path, '[[accept]]\npackage = "legacy-auth"\nreason = "r"\nuntil = 2000-01-01\n')
    stub(monkeypatch, [finding("legacy-auth")])
    assert cli.main(["scan", str(tmp_path), "--no-reachability"]) == cli.EXIT_FINDINGS


def test_a_broken_acceptance_file_is_a_usage_error_before_any_lookup(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("a==1.0\n", encoding="utf-8")
    write(tmp_path, '[[accept]]\npackage = "a"\n')
    called = []

    class Stub:
        def __init__(self, *a, **kw):
            called.append(1)

    monkeypatch.setattr(cli, "Analyzer", Stub)
    assert cli.main(["scan", str(tmp_path), "--no-reachability"]) == cli.EXIT_USAGE
    assert not called


def test_config_flag_points_at_another_file(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("legacy-auth==1.0\n", encoding="utf-8")
    custom = write(tmp_path, GOOD, "risks.toml")
    stub(monkeypatch, [finding("legacy-auth")])
    code = cli.main(["scan", str(tmp_path), "--no-reachability", "--config", str(custom)])
    assert code == cli.EXIT_OK
    assert "ACCEPTED RISK" in capsys.readouterr().out


def test_json_on_stdout_is_still_valid_with_acceptances(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("legacy-auth==1.0\nother==1.0\n", encoding="utf-8")
    write(tmp_path, GOOD + '\n[[accept]]\npackage = "gone"\nreason = "r"\nuntil = 2099-01-01\n')
    stub(monkeypatch, [finding("legacy-auth"), finding("other")])
    cli.main(["scan", str(tmp_path), "--no-reachability", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["accepted"] == 1


def test_explain_shows_the_acceptance(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("legacy-auth==1.0\n", encoding="utf-8")
    write(tmp_path, GOOD)
    stub(monkeypatch, [finding("legacy-auth")])
    code = cli.main(["explain", "legacy-auth", "--path", str(tmp_path), "--no-cache"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK, "accepted, so it does not fail"
    assert "Accepted risk" in out and "PROJ-123" in out


# --- the config file must not be able to exhaust memory ---------------------

def test_an_oversized_config_is_refused(tmp_path):
    from package_doctor.accept import MAX_CONFIG_BYTES

    path = tmp_path / "package-doctor.toml"
    path.write_bytes(b"accept = []\n" + b"#" * MAX_CONFIG_BYTES)
    with pytest.raises(ConfigError, match="larger than"):
        load_acceptances(tmp_path)


def test_a_config_exactly_at_the_cap_is_still_read(tmp_path):
    from package_doctor.accept import MAX_CONFIG_BYTES

    body = b"accept = []\n"
    path = tmp_path / "package-doctor.toml"
    path.write_bytes(body + b"#" * (MAX_CONFIG_BYTES - len(body)))
    assert path.stat().st_size == MAX_CONFIG_BYTES
    assert load_acceptances(tmp_path).entries == []


def test_the_config_read_is_bounded_not_just_size_checked(tmp_path, monkeypatch):
    """Rejecting an oversized file after buffering all of it defeats the cap:
    a checked-in config from an external PR is in memory before it is
    refused. The reader must never ask for more than one byte past the cap."""
    from package_doctor.accept import MAX_CONFIG_BYTES

    path = tmp_path / "package-doctor.toml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 4096))
    real_open = Path.open
    asked: list[int | None] = []

    class Bounded:
        def __init__(self, fh):
            self._fh = fh

        def read(self, size=-1):
            asked.append(size)
            return self._fh.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()

        def __getattr__(self, name):
            return getattr(self._fh, name)

    def bounded_open(self, *a, **kw):
        fh = real_open(self, *a, **kw)
        return Bounded(fh) if self.name == "package-doctor.toml" else fh

    monkeypatch.setattr(Path, "open", bounded_open)
    with pytest.raises(ConfigError, match="larger than"):
        load_acceptances(tmp_path)
    assert asked, "the file was not read through open()/read()"
    assert all(n is not None and 0 <= n <= MAX_CONFIG_BYTES + 1 for n in asked), asked
