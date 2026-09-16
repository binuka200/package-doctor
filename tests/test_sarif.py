"""SARIF: the shape other tools ingest.

A SARIF file that GitHub rejects is worse than none - the upload step fails
and the job goes red for a reason that has nothing to do with dependencies.
So the structure is checked field by field, and the two rules the report
lives by are checked here too: unknown is not a finding, and an accepted
risk is carried as a suppression rather than dropped.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from package_doctor import cli
from package_doctor.models import (
    Acceptance,
    AdvisoryHistory,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.sarif import RULES, to_sarif

NOW = dt.datetime(2026, 9, 13, 10, 30, tzinfo=dt.timezone.utc)


def make(name="demo", verdict=Verdict.REPLACE, **kw) -> Finding:
    return Finding(
        package=kw.pop("package", Package(name=name, version="1.0", origins=["requirements.txt"])),
        exposure=kw.pop("exposure", Exposure(categories=["crypto"],
                                             confidence=Confidence.CURATED)),
        remediation=kw.pop("remediation", Remediation()),
        verdict=verdict,
        reasons=kw.pop("reasons", [Evidence("repository is archived", "https://x.invalid")]),
    )


def test_the_envelope_is_sarif_2_1_0(tmp_path):
    doc = to_sarif([make()], tmp_path, NOW)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "package-doctor"
    assert driver["informationUri"].startswith("https://")
    assert run["automationDetails"]["id"] == "package-doctor/"
    assert run["invocations"][0]["endTimeUtc"] == "2026-09-13T10:30:00Z"
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].endswith("/")
    json.dumps(doc)  # serialisable


def test_every_rule_referenced_is_defined(tmp_path):
    findings = [make(v.value, v) for v in RULES]
    run = to_sarif(findings, tmp_path, NOW)["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        assert result["ruleId"] in ids
        assert ids[result["ruleIndex"]] == result["ruleId"]


def test_verdicts_map_to_levels(tmp_path):
    away = Exposure(categories=[], confidence=Confidence.CURATED)
    findings = [make("e", Verdict.EXPLOITED), make("r", Verdict.REPLACE),
                make("u", Verdict.UPGRADE), make("v", Verdict.MITIGATE),
                make("b", Verdict.UPGRADE, exposure=away), make("a", Verdict.QUIET)]
    run = to_sarif(findings, tmp_path, NOW)["runs"][0]
    assert [(r["properties"]["package"], r["level"]) for r in run["results"]] == [
        ("e", "error"), ("r", "error"), ("u", "error"), ("v", "warning"),
        # Away from a reviewed boundary the same rule is not an error: the
        # level follows the group, exactly as the exit code does.
        ("b", "warning"), ("a", "note"),
    ]


def test_unknown_and_ok_produce_no_result(tmp_path):
    """"We could not tell" is not an alert. Neither is "fine"."""
    run = to_sarif([make("u", Verdict.UNCHECKED), make("o", Verdict.OK)], tmp_path, NOW)["runs"][0]
    assert run["results"] == []


def test_import_sites_become_the_location_and_related_locations(tmp_path):
    pkg = Package(name="pillow", version="10.0.0",
                  import_sites=["api/upload.py:2", "api/thumbs.py:7", "tests/test_x.py:1"])
    result = to_sarif([make(package=pkg)], tmp_path, NOW)["runs"][0]["results"][0]
    primary = result["locations"]
    assert len(primary) == 1, "viewers show one location; the rest are related"
    loc = primary[0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "api/upload.py", "uriBaseId": "%SRCROOT%"}
    assert loc["region"] == {"startLine": 2}
    related = result["relatedLocations"]
    assert [r["physicalLocation"]["artifactLocation"]["uri"] for r in related] == [
        "api/thumbs.py", "tests/test_x.py",
    ]
    assert all("id" in r and r["message"]["text"] for r in related)


def test_a_package_never_imported_points_at_the_line_that_declared_it(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# deps\nrequests==2.0\nFlask_Login==0.6\n", encoding="utf-8"
    )
    pkg = Package(name="flask-login", version="0.6", origins=["requirements.txt"])
    result = to_sarif([make(package=pkg)], tmp_path, NOW)["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "requirements.txt"
    assert loc["region"] == {"startLine": 3}, "PEP 503 match: Flask_Login is flask-login"
    assert "relatedLocations" not in result


def test_a_name_that_is_a_prefix_of_another_does_not_match_the_wrong_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests-oauthlib==1\nrequests==2\n",
                                               encoding="utf-8")
    pkg = Package(name="requests", version="2", origins=["requirements.txt"])
    result = to_sarif([make(package=pkg)], tmp_path, NOW)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 2}


def test_a_missing_manifest_still_yields_a_location_without_a_line(tmp_path):
    pkg = Package(name="x", version="1", origins=["gone.txt"])
    result = to_sarif([make(package=pkg)], tmp_path, NOW)["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "gone.txt" and "region" not in loc


def test_the_message_carries_the_reasons_and_marks_an_assumed_version(tmp_path):
    pkg = Package(name="httpx", version="0.28.1", version_assumed=True)
    text = to_sarif([make(package=pkg)], tmp_path, NOW)["runs"][0]["results"][0]["message"]["text"]
    assert text.startswith("httpx 0.28.1 (assumed: nothing pins this package) - crypto.")
    assert "repository is archived" in text


def test_an_inferred_exposure_is_marked_as_a_guess(tmp_path):
    f = make(exposure=Exposure(categories=["crypto"], confidence=Confidence.INFERRED),
             verdict=Verdict.MITIGATE)
    result = to_sarif([f], tmp_path, NOW)["runs"][0]["results"][0]
    assert "(inferred, not reviewed)" in result["message"]["text"]
    assert result["properties"]["exposureConfidence"] == "inferred"


def test_an_accepted_finding_is_a_suppression_not_an_omission(tmp_path):
    f = make()
    f.accepted = Acceptance("demo", "PROJ-1 in flight", dt.date(2099, 1, 1),
                            source="package-doctor.toml")
    result = to_sarif([f], tmp_path, NOW)["runs"][0]["results"][0]
    sup = result["suppressions"][0]
    assert sup["kind"] == "external" and sup["status"] == "accepted"
    assert "PROJ-1 in flight" in sup["justification"] and "2099-01-01" in sup["justification"]


def test_an_expired_acceptance_is_not_a_suppression_and_the_message_says_why(tmp_path):
    f = make()
    f.accepted = Acceptance("demo", "PROJ-1", dt.date(2026, 1, 1), source="x")
    f.acceptance_expired = True
    result = to_sarif([f], tmp_path, NOW)["runs"][0]["results"][0]
    assert "suppressions" not in result
    assert "Acceptance expired on 2026-01-01: PROJ-1" in result["message"]["text"]


def test_properties_carry_what_a_dashboard_would_filter_on(tmp_path):
    rem = Remediation(advisories=AdvisoryHistory(ids_affecting_current=["CVE-2023-4863"]))
    rem.exploitability.kev = ["CVE-2023-4863"]
    pkg = Package(name="pillow", version="10.0.0", direct=False)
    run = to_sarif([make(package=pkg, remediation=rem)], tmp_path, NOW)["runs"][0]
    props = run["results"][0]["properties"]
    assert props["direct"] is False
    assert props["advisoriesAffectingVersion"] == ["CVE-2023-4863"]
    assert props["knownExploited"] == ["CVE-2023-4863"]
    assert props["verdict"] == "replace"


def test_fingerprint_is_the_package_so_alerts_persist_across_runs(tmp_path):
    result = to_sarif([make("pyjwt")], tmp_path, NOW)["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {"package-doctor/package": "pyjwt"}


# --- through the CLI --------------------------------------------------------

def stub(monkeypatch, findings):
    class Stub:
        def __init__(self, *a, **kw):
            pass

        async def analyze_all(self, packages, now, progress=None):
            return findings

    monkeypatch.setattr(cli, "Analyzer", Stub)


def test_sarif_is_written_even_when_the_scan_fails_the_build(tmp_path, monkeypatch):
    """The upload step needs the file most exactly when there are findings."""
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    stub(monkeypatch, [make()])
    out = tmp_path / "r.sarif"
    code = cli.main(["scan", str(tmp_path), "--no-reachability", "--sarif", str(out)])
    assert code == cli.EXIT_FINDINGS
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"][0]["ruleId"] == "package-doctor/replace"


def test_sarif_and_json_on_stdout_do_not_collide(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    stub(monkeypatch, [make()])
    out = tmp_path / "r.sarif"
    cli.main(["scan", str(tmp_path), "--no-reachability", "--json", "--sarif", str(out)])
    stdout, stderr = capsys.readouterr()
    json.loads(stdout)
    assert "Wrote" in stderr and "Wrote" not in stdout


@pytest.mark.parametrize("flag", ["--sarif", "--markdown"])
def test_side_outputs_are_paths(flag, tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    stub(monkeypatch, [make()])
    target = tmp_path / "out"
    cli.main(["scan", str(tmp_path), "--no-reachability", flag, str(target)])
    assert Path(target).is_file()
