"""Rendering, and the JSON other tools would build on."""

from __future__ import annotations

import datetime as dt

import pytest
from rich.console import Console

from package_doctor.models import (
    AdvisoryHistory,
    Confidence,
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.report import render, render_explain, to_dict

NOW = dt.datetime(2026, 9, 12, tzinfo=dt.timezone.utc)


def console() -> Console:
    # Fixed width so wrapping cannot differ between a terminal and CI.
    return Console(width=100, force_terminal=False)


def make(name="demo", verdict=Verdict.ACT, **kw) -> Finding:
    return Finding(
        package=kw.pop("package", Package(name=name, version="1.0")),
        exposure=kw.pop("exposure", Exposure(categories=["crypto"],
                                             confidence=Confidence.CURATED)),
        remediation=kw.pop("remediation", Remediation()),
        verdict=verdict,
        reasons=kw.pop("reasons", [Evidence("because", "https://example.invalid")]),
    )


@pytest.mark.parametrize("verdict", list(Verdict))
def test_every_verdict_renders(verdict, capsys):
    render(console(), [make(verdict=verdict)], sources=["requirements.txt"], show_ok=True)
    assert capsys.readouterr().out.strip()


def test_an_empty_scan_says_so(capsys):
    render(console(), [], sources=[])
    assert "Nothing to act on" in capsys.readouterr().out


def test_sections_are_labelled_by_what_to_do(capsys):
    render(console(), [make("a", Verdict.ACT), make("b", Verdict.WATCH)],
           sources=["requirements.txt"])
    out = capsys.readouterr().out
    assert "act on these" in out and "watch" in out
    # The actionable section must come first.
    assert out.index("NO ONE HOME") < out.index("EXPOSED, MAINTAINED")


def test_there_is_no_aggregate_score_anywhere(capsys):
    """A single health number is the thing users cannot act on. Its absence is
    a design commitment, not an oversight."""
    render(console(), [make()], sources=["requirements.txt"])
    out = capsys.readouterr().out.lower()
    assert "score" not in out
    assert "/100" not in out


def test_ok_packages_are_hidden_unless_asked_for(capsys):
    render(console(), [make("quiet", Verdict.OK)], sources=["r.txt"])
    assert "quiet" not in capsys.readouterr().out
    render(console(), [make("quiet", Verdict.OK)], sources=["r.txt"], show_ok=True)
    assert "quiet" in capsys.readouterr().out


def test_known_exploited_sorts_above_a_larger_advisory_count(capsys):
    """Being exploited today beats having more advisories."""
    loud = make("loud", remediation=Remediation(
        advisories=AdvisoryHistory(total=50, unfixed=9, affecting_current=40)))
    exploited = make("exploited", remediation=Remediation(
        advisories=AdvisoryHistory(total=2, affecting_current=1),
        exploitability=Exploitability(kev=["CVE-2023-4863"], checked=True)))
    render(console(), [loud, exploited], sources=["r.txt"])
    out = capsys.readouterr().out
    assert out.index("exploited") < out.index("loud")


def test_imported_packages_sort_above_unimported(capsys):
    absent = make("absent", package=Package(name="absent", version="1.0",
                                            reachability_checked=True))
    used = make("used", package=Package(name="used", version="1.0",
                                        import_sites=["app.py:1"],
                                        reachability_checked=True))
    render(console(), [absent, used], sources=["r.txt"])
    out = capsys.readouterr().out
    assert out.index("used") < out.index("absent")


# --- explain ----------------------------------------------------------------

def test_explain_renders_with_no_data_at_all(capsys):
    render_explain(console(), make(verdict=Verdict.UNKNOWN, remediation=Remediation(
        gaps=["no source repository declared on PyPI"])))
    out = capsys.readouterr().out
    assert "no source repository" in out


def test_explain_states_that_an_empty_record_is_unknown(capsys):
    render_explain(console(), make(verdict=Verdict.WATCH))
    assert "not good" in capsys.readouterr().out


def test_explain_warns_that_no_import_is_not_safety(capsys):
    render_explain(console(), make(package=Package(
        name="demo", version="1.0", reachability_checked=True)))
    assert "Not a safety finding" in capsys.readouterr().out


def test_explain_never_prints_a_flat_hundred_percent(capsys):
    """EPSS tops out just short of 1.0; printing certainty it does not claim
    would be its own small lie."""
    render_explain(console(), make(remediation=Remediation(
        advisories=AdvisoryHistory(total=1, affecting_current=1),
        exploitability=Exploitability(kev=["CVE-1"], scored=[("CVE-1", 0.99979)],
                                      checked=True, queried=1))))
    out = capsys.readouterr().out
    assert ">99%" in out and "100.0%" not in out


# --- json -------------------------------------------------------------------

def test_json_shape_is_stable():
    payload = to_dict([make()], ["requirements.txt"], NOW)
    assert payload["schema_version"] == 1
    assert payload["sources"] == ["requirements.txt"]
    row = payload["findings"][0]
    for key in ("name", "version", "direct", "verdict", "exposure",
                "remediation", "reasons", "reachability"):
        assert key in row, key
    for key in ("advisories", "exploitability", "missing_signals", "repository"):
        assert key in row["remediation"], key


def test_json_counts_every_verdict():
    payload = to_dict([make("a", Verdict.ACT), make("b", Verdict.ACT),
                       make("c", Verdict.OK)], [], NOW)
    assert payload["counts"] == {"act": 2, "ok": 1}


def test_json_preserves_evidence_urls():
    row = to_dict([make()], [], NOW)["findings"][0]
    assert row["reasons"][0]["url"] == "https://example.invalid"


def test_explain_says_when_no_version_was_known():
    """Without a version, advisory matching never ran. The section would
    otherwise read as a clean bill of health for the reader's install."""
    import io

    from rich.console import Console

    from package_doctor.models import (
        AdvisoryHistory,
        Confidence,
        Exposure,
        Finding,
        Package,
        Remediation,
        Verdict,
    )
    from package_doctor.report import render_explain

    def out_for(version):
        buf = io.StringIO()
        finding = Finding(
            package=Package(name="pillow", version=version),
            exposure=Exposure(categories=["file/media parsing"], confidence=Confidence.CURATED),
            remediation=Remediation(advisories=AdvisoryHistory(total=153, timely=147)),
            verdict=Verdict.WATCH,
        )
        render_explain(Console(file=buf, width=100, force_terminal=False), finding)
        return buf.getvalue()

    assert "advisory matching skipped" in out_for(None)
    assert "--pin" in out_for(None)
    assert "advisory matching skipped" not in out_for("10.0.0")
