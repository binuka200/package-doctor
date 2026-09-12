"""Rendering.

Findings are grouped by what the user should do about them, never sorted by a
score. There is deliberately no aggregate number anywhere in this file: a single
health score is the thing users cannot act on and maintainers cannot argue with.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict
from typing import Any, Iterable

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .models import Confidence, Finding, Verdict

SECTIONS: list[tuple[Verdict, str, str, str]] = [
    (Verdict.ACT, "EXPOSED + NO ONE HOME", "act on these", "bold red"),
    (Verdict.WATCH, "EXPOSED, MAINTAINED", "watch", "yellow"),
    (Verdict.LOW, "STALE, NOT EXPOSED", "low priority", "cyan"),
    (Verdict.UNKNOWN, "NO SIGNAL", "unknown, not a finding", "dim"),
]


def _version(finding: Finding) -> str:
    return finding.package.version or "-"


def _sort_key(finding: Finding) -> tuple:
    """Most consequential first, within a section.

    Weak signals count here even though they were not enough to escalate: a
    package carrying "no release in 5.9y" belongs above one with nothing to
    report, even when both are only worth watching.
    """
    adv = finding.remediation.advisories
    pkg = finding.package
    # Reachability leads. A package your code demonstrably imports is more
    # actionable than a more-alarming one you may never reach - which is the
    # whole point of checking. Severity breaks ties within each band.
    if pkg.is_imported:
        reach_rank = 1 if pkg.imported_in_tests_only else 0
    else:
        reach_rank = 2
    return (
        reach_rank,
        -adv.unfixed,
        -adv.affecting_current,
        -len(finding.abandonment_signals),
        0 if pkg.direct else 1,
        pkg.name,
    )


def render(
    console: Console,
    findings: list[Finding],
    *,
    sources: Iterable[str],
    show_ok: bool = False,
    now: dt.datetime | None = None,
) -> None:
    total = len(findings)
    direct = sum(1 for f in findings if f.package.direct)
    src = ", ".join(sources) or "no dependency files"

    console.print()
    header = Text("Dependency Risk Report", style="bold")
    header.append(f"   {total} packages · {direct} direct", style="dim")
    console.print(header)
    console.print(Text(f"from {src}", style="dim"))

    by_verdict: dict[Verdict, list[Finding]] = {}
    for finding in findings:
        by_verdict.setdefault(finding.verdict, []).append(finding)

    shown = 0
    for verdict, title, hint, style in SECTIONS:
        group = sorted(by_verdict.get(verdict, []), key=_sort_key)
        if not group:
            continue
        shown += len(group)
        console.print()
        line = Text(title, style=style)
        line.append(f"   {hint}", style="dim")
        console.print(line)

        table = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
        table.add_column("name", style="bold", no_wrap=True)
        table.add_column("version", style="dim", no_wrap=True)
        table.add_column("exposure", no_wrap=True)
        table.add_column("why")

        for finding in group:
            reasons = finding.reasons[:2]
            why = Text()
            for i, reason in enumerate(reasons):
                if i:
                    why.append("\n")
                why.append(reason.claim)
            if not reasons:
                why.append("-", style="dim")
            extra = len(finding.reasons) - len(reasons)
            if extra > 0:
                why.append(f"  (+{extra} more)", style="dim")

            exposure_text = Text(finding.exposure.label)
            if finding.exposure.confidence is Confidence.INFERRED and finding.exposure.is_exposed:
                exposure_text.append("?", style="dim")

            table.add_row(finding.package.name, _version(finding), exposure_text, why)
        console.print(table)

    ok = by_verdict.get(Verdict.OK, [])
    if show_ok and ok:
        console.print()
        console.print(Text("OK", style="green"))
        table = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
        table.add_column("name", style="bold", no_wrap=True)
        table.add_column("version", style="dim")
        for finding in sorted(ok, key=_sort_key):
            table.add_row(finding.package.name, _version(finding))
        console.print(table)

    console.print()
    summary = Text()
    counts = [
        ("act on", len(by_verdict.get(Verdict.ACT, [])), "red"),
        ("watch", len(by_verdict.get(Verdict.WATCH, [])), "yellow"),
        ("low", len(by_verdict.get(Verdict.LOW, [])), "cyan"),
        ("unknown", len(by_verdict.get(Verdict.UNKNOWN, [])), "dim"),
        ("ok", len(ok), "green"),
    ]
    for i, (label, count, colour) in enumerate(counts):
        if i:
            summary.append("   ")
        summary.append(f"{count} ", style=f"bold {colour}")
        summary.append(label, style="dim")
    console.print(summary)

    if not shown:
        console.print(Text("Nothing to act on.", style="green"))
    else:
        console.print(
            Text("package-doctor explain <name> for the evidence behind a row", style="dim")
        )
    console.print()


def render_explain(console: Console, finding: Finding, exposure_note: str = "") -> None:
    pkg = finding.package
    rem = finding.remediation
    adv = rem.advisories

    console.print()
    title = Text(f"{pkg.name} {pkg.version or ''}".strip(), style="bold")
    style = {
        Verdict.ACT: "bold red",
        Verdict.WATCH: "yellow",
        Verdict.LOW: "cyan",
        Verdict.UNKNOWN: "dim",
        Verdict.OK: "green",
    }[finding.verdict]
    label = {
        Verdict.ACT: "ACT ON THIS",
        Verdict.WATCH: "WATCH",
        Verdict.LOW: "LOW PRIORITY",
        Verdict.UNKNOWN: "NO SIGNAL",
        Verdict.OK: "OK",
    }[finding.verdict]
    title.append(f"    {label}", style=style)
    console.print(title)

    def section(name: str) -> None:
        console.print()
        console.print(Text(name, style="bold"))

    def row(key: str, value: str, value_style: str = "") -> None:
        line = Text("  ")
        line.append(f"{key:<26}", style="dim")
        line.append(value, style=value_style)
        console.print(line)

    section("Exposure")
    row("Category", finding.exposure.label)
    row(
        "Source",
        {
            Confidence.CURATED: "curated (human-reviewed)",
            Confidence.INFERRED: "inferred from PyPI metadata",
            Confidence.NONE: "no data",
        }[finding.exposure.confidence],
    )
    if exposure_note:
        row("Means", exposure_note)
    if finding.exposure.note:
        row("Note", finding.exposure.note)
    row("Dependency", "direct" if pkg.direct else "transitive")
    if pkg.origins:
        row("Declared in", ", ".join(sorted(pkg.origins)))

    section("Reachability")
    if pkg.import_sites:
        row("Imported by your code", "yes" + (" (test code only)" if pkg.imported_in_tests_only else ""))
        for site in pkg.import_sites[:6]:
            console.print(Text(f"    {site}", style="dim"))
        if len(pkg.import_sites) > 6:
            console.print(Text(f"    (+{len(pkg.import_sites) - 6} more)", style="dim"))
    elif pkg.reachability_checked:
        row("Imported by your code", "no direct import found")
        console.print(
            Text(
                "    Not a safety finding: your dependencies call each other, so\n"
                "    this can still run without appearing in your source.",
                style="dim",
            )
        )
    else:
        row("Imported by your code", "not checked")
        console.print(Text("    Run `package-doctor scan` in the project to check.", style="dim"))

    section("Remediation capacity")
    row("Latest release", rem.latest_version or "unknown")
    if rem.last_release:
        row("Released", rem.last_release.date().isoformat())
    row(
        "Repository",
        "archived" if rem.repo_archived else ("active" if rem.repo_archived is False else "unknown"),
        "red" if rem.repo_archived else "",
    )
    if rem.repo_last_push:
        row("Last commit", rem.repo_last_push.date().isoformat())
    if rem.inactive_classifier:
        row("PyPI status", "Development Status :: 7 - Inactive", "red")
    if rem.open_issues is not None:
        row("Open issues", str(rem.open_issues))

    section("Security track record")
    if not adv.has_signal:
        row("Advisories", "none on record", "dim")
        row("Reading", "no history means unknown, not good", "dim")
    else:
        row("Advisories", str(adv.total))
        row(
            "Fixed before disclosure",
            f"{adv.timely} of {adv.total}",
            "green" if adv.timely and not adv.unfixed else "",
        )
        if adv.late:
            row(
                "Fixed after disclosure",
                f"{adv.late}"
                + (f" (median {adv.median_late_days:.0f}d exposed)" if adv.median_late_days else ""),
                "yellow",
            )
        if adv.unfixed:
            row("Never fixed", f"{adv.unfixed}  {', '.join(adv.ids_unfixed[:4])}", "bold red")
        if adv.affecting_current:
            row(
                "Affecting your version",
                f"{adv.affecting_current}  {', '.join(adv.ids_affecting_current[:4])}",
                "bold red",
            )
        if adv.unmatched:
            row("Not datable", str(adv.unmatched), "dim")

    if rem.gaps:
        section("Missing signals")
        for gap in rem.gaps:
            console.print(Text(f"  {gap}", style="dim"))

    if finding.reasons:
        section("Why this verdict")
        for reason in finding.reasons:
            line = Text("  • ")
            line.append(reason.claim)
            console.print(line)
            if reason.url:
                console.print(Text(f"    {reason.url}", style="dim blue"))

    section("Evidence")
    console.print(Text(f"  https://pypi.org/project/{pkg.name}/", style="dim blue"))
    if rem.repo_url:
        console.print(Text(f"  {rem.repo_url}", style="dim blue"))
    if adv.has_signal:
        console.print(
            Text(f"  https://osv.dev/list?q={pkg.name}&ecosystem=PyPI", style="dim blue")
        )
    console.print()


def to_dict(findings: list[Finding], sources: Iterable[str], now: dt.datetime) -> dict[str, Any]:
    def serialise(finding: Finding) -> dict[str, Any]:
        rem = finding.remediation
        return {
            "name": finding.package.name,
            "version": finding.package.version,
            "direct": finding.package.direct,
            "origins": sorted(finding.package.origins),
            "reachability": {
                "checked": finding.package.reachability_checked,
                "imported": finding.package.is_imported,
                "tests_only": finding.package.imported_in_tests_only,
                "sites": finding.package.import_sites,
            },
            "verdict": finding.verdict.value,
            "exposure": {
                "categories": finding.exposure.categories,
                "confidence": finding.exposure.confidence.value,
                "note": finding.exposure.note,
            },
            "remediation": {
                "latest_version": rem.latest_version,
                "last_release": rem.last_release.isoformat() if rem.last_release else None,
                "repository": rem.repo_url,
                "repo_archived": rem.repo_archived,
                "repo_last_push": rem.repo_last_push.isoformat() if rem.repo_last_push else None,
                "inactive_classifier": rem.inactive_classifier,
                "open_issues": rem.open_issues,
                "advisories": asdict(rem.advisories),
                "missing_signals": rem.gaps,
            },
            "reasons": [{"claim": r.claim, "url": r.url} for r in finding.reasons],
            "error": finding.error,
        }

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict.value] = counts.get(finding.verdict.value, 0) + 1

    return {
        "tool": "package-doctor",
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "sources": list(sources),
        "counts": counts,
        "findings": [serialise(f) for f in findings],
    }
