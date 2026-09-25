"""SARIF output, so findings show up where code review already happens.

GitHub code scanning, GitLab and most security dashboards ingest SARIF 2.1.0.
Each finding becomes one result; the verdict is the rule, the import sites
are the locations, and an accepted risk is carried as a SARIF suppression
rather than dropped - the dashboard then shows it as dismissed with the
reason, which is exactly how the report treats it.

Only the verdicts that ask something of the reader are emitted. *Unchecked*
is "we could not tell", which the model treats as not a finding, and *ok* is
nothing at all; either would be an alert that can never be resolved.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

from . import __version__
from .models import Confidence, Finding, Verdict

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
HOMEPAGE = "https://github.com/binuka200/package-doctor"

#: Verdict -> (rule id, SARIF level, short description, full description).
#:
#: The rule ids are stable identifiers other tools key on; the wording can
#: change, the ids should not.
RULES: dict[Verdict, tuple[str, str, str, str]] = {
    Verdict.EXPLOITED: (
        "package-doctor/exploited",
        "error",
        "Known-exploited vulnerability in the version in use",
        "The version in use is affected by a CVE on CISA's Known Exploited "
        "Vulnerabilities catalogue: the flaw has been used against real targets. "
        "Fix today.",
    ),
    Verdict.REPLACE: (
        "package-doctor/replace",
        "error",
        "Dependency with no one left to fix it",
        "The repository is archived or the maintainer marked the project Inactive, "
        "or the version in use carries an advisory with no fix anywhere and the "
        "project has gone quiet. Plan a migration.",
    ),
    Verdict.UPGRADE: (
        "package-doctor/upgrade",
        "error",
        "Advisories fixed in a newer release",
        "The version in use is affected by published advisories that a newer "
        "release no longer carries. Upgrade.",
    ),
    Verdict.MITIGATE: (
        "package-doctor/mitigate",
        "warning",
        "Advisory with no fix anywhere",
        "The version in use is affected by an advisory that no release fixes, in a "
        "project that is still active. Upgrading cannot clear it: work around it, "
        "or press upstream.",
    ),
    Verdict.QUIET: (
        "package-doctor/quiet",
        "note",
        "Dependency has gone quiet",
        "Nothing is wrong with the version in use, but the project has not shipped "
        "in a long time. Worth knowing before a fix is needed.",
    ),
}


def _line_naming(path: Path, name: str) -> int | None:
    """First line of a dependency file that names the package, or None.

    A finding with no import site still needs somewhere to point: the file
    that declared the dependency, at the line that did so, is what the reader
    would open next. Names are matched under PEP 503 rules, so ``Flask_Login``
    in a requirements file matches the finding for ``flask-login``.
    """
    pattern = re.compile(
        r"(?<![A-Za-z0-9_.-])" + r"[-_.]+".join(map(re.escape, name.split("-")))
        + r"(?![A-Za-z0-9_.-])",
        re.IGNORECASE,
    )
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if pattern.search(line):
                    return number
    except OSError:
        return None
    return None


#: Import sites beyond the first are related locations, and this many is
#: enough for anyone: a package imported from two hundred files is a fact
#: about the project, not two hundred facts about the package.
MAX_RELATED = 20


def _locations(finding: Finding, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(primary locations, related locations) for one finding.

    Viewers show the first entry of ``locations`` as *the* place; the rest
    are ignored by most of them. So the first import site is the location,
    the other sites are ``relatedLocations``, and a package the source never
    imports points at the dependency file that declared it.
    """
    sites: list[dict[str, Any]] = []
    for site in finding.package.import_sites:
        file, _, line = site.rpartition(":")
        if not file or not line.isdigit():
            continue
        sites.append(_location(file, int(line)))
    if sites:
        related = sites[1 : MAX_RELATED + 1]
        for i, loc in enumerate(related):
            loc["id"] = i
            loc["message"] = {"text": "also imported here"}
        return sites[:1], related
    declared = [
        _location(origin, _line_naming(root / origin, finding.package.name))
        for origin in sorted(finding.package.origins)
    ]
    return declared[:1], declared[1:]


def _location(uri: str, line: int | None) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": uri.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
    }
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _message(finding: Finding) -> str:
    pkg = finding.package
    version = pkg.version or "unpinned"
    if pkg.version_assumed and pkg.specifier:
        version = f"{pkg.version} (assumed: the newest release {pkg.specifier} allows)"
    elif pkg.version_assumed:
        version = f"{pkg.version} (assumed: nothing pins this package)"
    head = f"{pkg.name} {version}"
    exposure = finding.exposure.label
    if finding.exposure.confidence is Confidence.INFERRED and finding.exposure.is_exposed:
        exposure += " (inferred, not reviewed)"
    lines = [f"{head} - {exposure}."]
    lines.extend(r.claim for r in finding.reasons)
    if finding.accepted is not None and finding.acceptance_expired:
        lines.append(
            f"Acceptance expired on {finding.accepted.until.isoformat()}: "
            f"{finding.accepted.reason}"
        )
    return "\n".join(lines)


def to_sarif(findings: list[Finding], root: Path, now: dt.datetime) -> dict[str, Any]:
    rules = [
        {
            "id": rule_id,
            "name": rule_id.split("/")[-1],
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "help": {"text": full, "markdown": full},
            "helpUri": f"{HOMEPAGE}#the-two-axis-model",
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "supply-chain"]},
        }
        for rule_id, level, short, full in RULES.values()
    ]
    rule_index = {rule_id: i for i, (rule_id, *_) in enumerate(RULES.values())}

    results: list[dict[str, Any]] = []
    for finding in findings:
        rule = RULES.get(finding.verdict)
        if rule is None:
            continue
        rule_id, level, *_ = rule
        # A finding that does not fail a build must not arrive as an `error` in
        # a dashboard: the level follows the group, the same way the exit code
        # does. `note` stays `note` wherever it is found.
        if level == "error" and not finding.blocks:
            level = "warning"
        locations, related = _locations(finding, root)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": level,
            "message": {"text": _message(finding)},
            "locations": locations,
            # A stable identity across runs, so the same package is the same
            # alert tomorrow rather than a new one every scan.
            "partialFingerprints": {"package-doctor/package": finding.package.name},
            "properties": {
                "package": finding.package.name,
                "version": finding.package.version,
                "versionAssumed": finding.package.version_assumed,
                "direct": finding.package.direct,
                "verdict": finding.verdict.value,
                "exposure": finding.exposure.categories,
                "boundary": finding.exposure.boundary.value,
                "blocks": finding.blocks and not finding.suppressed,
                "exposureConfidence": finding.exposure.confidence.value,
                "consequence": finding.exposure.consequence,
                "advisoriesAffectingVersion": (
                    finding.remediation.advisories.ids_affecting_current
                ),
                "knownExploited": finding.remediation.exploitability.kev,
            },
        }
        if related:
            result["relatedLocations"] = related
        if finding.suppressed and finding.accepted is not None:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": (
                        f"{finding.accepted.reason} "
                        f"(until {finding.accepted.until.isoformat()}, "
                        f"{finding.accepted.source})"
                    ),
                }
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "package-doctor",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": HOMEPAGE,
                        "rules": rules,
                    }
                },
                # Distinguishes this upload from other SARIF producers in the
                # same workflow, so their alerts are not closed as "fixed".
                "automationDetails": {"id": "package-doctor/"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now.astimezone(dt.timezone.utc)
                        .replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                ],
                "originalUriBaseIds": {"%SRCROOT%": {"uri": root.as_uri() + "/"}},
                "results": results,
            }
        ],
    }
