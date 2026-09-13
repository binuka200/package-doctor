"""Rendering.

Findings are grouped by what the user should do about them, never sorted by a
score. There is deliberately no aggregate number anywhere in this file: a single
health score is the thing users cannot act on and maintainers cannot argue with.
"""

from __future__ import annotations

import datetime as dt
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import asdict
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .exposure import consequence_rank
from .models import Confidence, Finding, Verdict


def clean(value: object) -> str:
    """Strip control and format characters before anything reaches a terminal.

    rich's ``Text`` neutralises *markup*, but it passes raw escape sequences
    through, so a version string in a lockfile, a file name in the scanned
    tree, or a URL in an API response could otherwise clear the screen, retitle
    the window, or wrap itself in an OSC 8 hyperlink that points somewhere else
    than it appears to. Every string that originates outside this process goes
    through here on its way to the console. The JSON output does not need it:
    ``json.dumps`` escapes these already.

    Unicode category Cc is the C0/C1 controls (ESC included); Cf is the
    invisible formatting set, which covers the bidi overrides used to make text
    read differently from how it is written.
    """
    text = _ESCAPE_SEQUENCE.sub("", str(value))
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


#: Whole CSI and OSC sequences, removed before the character-level pass so that
#: "\x1b[31m" leaves nothing behind rather than a stray "[31m". Anything the
#: pattern does not recognise still loses its ESC, which is what makes it inert.
_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"          # CSI: ESC [ params intermediates final
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC: ESC ] ... BEL or ESC \
)

SECTIONS: list[tuple[Verdict, str, str, str]] = [
    (Verdict.ACT, "EXPOSED + NO ONE HOME", "act on these", "bold red"),
    (Verdict.WATCH, "EXPOSED, MAINTAINED", "watch", "yellow"),
    (Verdict.LOW, "STALE, NOT EXPOSED", "low priority", "cyan"),
    (Verdict.UNKNOWN, "NO SIGNAL", "unknown, not a finding", "dim"),
]


def _version(finding: Finding) -> str:
    """The version column. An assumed version carries ``?``, the same mark an
    inferred exposure carries: something the reader should distrust."""
    if not finding.package.version:
        return "-"
    version = clean(finding.package.version)
    return f"{version}?" if finding.package.version_assumed else version


def _until(finding: Finding, now: dt.datetime | None) -> str:
    """"until 2026-12-31 (in 3 months)" - the expiry, with how far off it is."""
    assert finding.accepted is not None
    until = finding.accepted.until
    text = f"until {until.isoformat()}"
    if now is not None:
        days = (until - now.date()).days
        if days < 0:
            text = f"expired {until.isoformat()} ({-days} day{'s' if days != -1 else ''} ago)"
        elif days == 0:
            text += " (today)"
        elif days < 60:
            text += f" (in {days} day{'s' if days != 1 else ''})"
        else:
            months = round(days / 30.44)
            text += f" (in {months} month{'s' if months != 1 else ''})"
    return text


def _pin_note(findings: list[Finding]) -> tuple[str, str] | None:
    """The header line about unpinned packages, or None when all are pinned.

    Two different facts share this line, and the reader must be able to tell
    them apart: matched against an assumed version (marked ``?`` in the
    table, worth distrusting) versus not matched at all.
    """
    total = len(findings)
    assumed = sum(1 for f in findings if f.package.version_assumed)
    skipped = sum(1 for f in findings if not f.package.version)
    if not assumed and not skipped:
        return None
    parts = []
    if assumed:
        parts.append(
            f"{assumed} of {total} without a pinned version: advisories matched "
            f"against the newest release instead, marked ? (use a lockfile to pin them)"
        )
    if skipped:
        parts.append(
            f"{skipped} of {total} without a pinned version: advisory matching "
            f"skipped for those (use a lockfile to pin them)"
        )
    return "\n".join(parts), "yellow"


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
    reach_rank = (1 if pkg.imported_in_tests_only else 0) if pkg.is_imported else 2
    exploit = finding.remediation.exploitability
    top = exploit.top
    return (
        # Known-exploited beats everything: these are in use against real
        # targets, not predicted to be.
        0 if exploit.kev else 1,
        reach_rank,
        -adv.unfixed,
        # Exploit probability orders the rest; an advisory count does not.
        -(top[1] if top else 0.0),
        -adv.affecting_current,
        # With the same evidence, what a flaw would cost decides: a stale
        # pickle loader above a stale JSON parser. A word from a fixed
        # vocabulary, never a score.
        consequence_rank(finding.exposure.consequence),
        -len(finding.abandonment_signals),
        0 if pkg.direct else 1,
        pkg.name,
    )


def describe_degraded(degraded: dict[str, int] | None) -> str | None:
    """One line saying which upstream failed, or None when none did."""
    if not degraded:
        return None
    parts = [
        f"{n} request{'s' if n != 1 else ''} to {host}" for host, n in sorted(degraded.items())
    ]
    return (
        "Upstream trouble: " + ", ".join(parts) + " failed after retries. "
        "The affected packages show gaps, not results; rerun later to fill them."
    )


def render(
    console: Console,
    findings: list[Finding],
    *,
    sources: Iterable[str],
    show_ok: bool = False,
    now: dt.datetime | None = None,
    degraded: dict[str, int] | None = None,
    notes: Iterable[str] = (),
) -> None:
    total = len(findings)
    direct = sum(1 for f in findings if f.package.direct)
    src = ", ".join(sources) or "no dependency files"

    console.print()
    header = Text("Dependency Risk Report", style="bold")
    header.append(f"   {total} packages · {direct} direct", style="dim")
    console.print(header)
    console.print(Text(f"from {src}", style="dim"))
    pin_note = _pin_note(findings)
    if pin_note:
        # Advisory matching needs a version. Without one the package can still
        # be judged on maintenance, but "no advisories" must not be implied.
        console.print(Text(pin_note[0], style=pin_note[1]))

    # Accepted findings leave their verdict section for one of their own. The
    # verdict is unchanged; only where it is shown and whether it fails the
    # build. An expired acceptance stays put, and its row says it expired.
    accepted = [f for f in findings if f.suppressed]
    by_verdict: dict[Verdict, list[Finding]] = {}
    for finding in findings:
        if finding.suppressed:
            continue
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
        # Wrap a long name rather than clipping it: "djangorestframework-sim…"
        # is not a package anyone can look up or install.
        table.add_column("name", style="bold", overflow="fold", max_width=22)
        table.add_column("version", style="dim", no_wrap=True)
        table.add_column("exposure", no_wrap=True)
        # Wrap rather than truncate: a clipped file path or advisory id is
        # worse than useless, because the user cannot look it up.
        table.add_column("why", overflow="fold")

        for finding in group:
            reasons = finding.reasons[:2]
            why = Text()
            for i, reason in enumerate(reasons):
                if i:
                    why.append("\n")
                why.append(clean(reason.claim))
            if not reasons:
                why.append("-", style="dim")
            extra = len(finding.reasons) - len(reasons)
            if extra > 0:
                # Worded, not another "(+N more)": reason claims can end in
                # their own "(+79 more)" and two bare counts side by side read
                # as one confusing number.
                why.append(
                    f"\nand {extra} more reason{'s' if extra > 1 else ''} "
                    f"- package-doctor explain {clean(finding.package.name)}",
                    style="dim",
                )
            if finding.accepted is not None and finding.acceptance_expired:
                # Back in its verdict section because the acceptance ran out,
                # not because anything about the package changed. Say which.
                why.append(
                    f"\nacceptance {_until(finding, now)}: "
                    f"{clean(finding.accepted.reason)}",
                    style="yellow",
                )

            exposure_text = Text(finding.exposure.label)
            if finding.exposure.confidence is Confidence.INFERRED and finding.exposure.is_exposed:
                exposure_text.append("?", style="dim")

            table.add_row(clean(finding.package.name), _version(finding), exposure_text, why)
        console.print(table)

    if accepted:
        console.print()
        line = Text("ACCEPTED RISK", style="magenta")
        line.append("   on the record, not failing the build", style="dim")
        console.print(line)
        table = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
        table.add_column("name", style="bold", overflow="fold", max_width=22)
        table.add_column("version", style="dim", no_wrap=True)
        table.add_column("verdict", no_wrap=True)
        table.add_column("why", overflow="fold")
        labels = {v: hint for v, _, hint, _ in SECTIONS}
        for finding in sorted(accepted, key=_sort_key):
            assert finding.accepted is not None
            why = Text(clean(finding.accepted.reason))
            why.append(f"\n{_until(finding, now)}", style="dim")
            table.add_row(
                clean(finding.package.name),
                _version(finding),
                Text(labels.get(finding.verdict, finding.verdict.value), style="dim"),
                why,
            )
        console.print(table)

    ok = by_verdict.get(Verdict.OK, [])
    if show_ok and ok:
        console.print()
        console.print(Text("OK", style="green"))
        table = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
        # Wrap a long name rather than clipping it: "djangorestframework-sim…"
        # is not a package anyone can look up or install.
        table.add_column("name", style="bold", overflow="fold", max_width=22)
        table.add_column("version", style="dim")
        for finding in sorted(ok, key=_sort_key):
            table.add_row(clean(finding.package.name), _version(finding))
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
    if accepted:
        counts.append(("accepted", len(accepted), "magenta"))
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
    note = describe_degraded(degraded)
    if note:
        console.print(Text(note, style="yellow"))
    for line in notes:
        console.print(Text(clean(line), style="dim"))
    console.print()


def _md_cell(value: object) -> str:
    """One Markdown table cell: control characters out (newlines with them),
    pipes escaped so a claim cannot break out of its column."""
    return clean(value).replace("|", "\\|")


def render_markdown(
    findings: list[Finding],
    *,
    sources: Iterable[str],
    now: dt.datetime | None = None,
    degraded: dict[str, int] | None = None,
    notes: Iterable[str] = (),
) -> str:
    """The report as GitHub-flavoured Markdown, for a job's step summary.

    Same sections, same order, same rule that accepted findings are shown
    and never dropped. Nothing here that the terminal report would not say.
    """
    total = len(findings)
    direct = sum(1 for f in findings if f.package.direct)
    src = ", ".join(_md_cell(s) for s in sources) or "no dependency files"
    accepted = [f for f in findings if f.suppressed]
    by_verdict: dict[Verdict, list[Finding]] = {}
    for finding in findings:
        if not finding.suppressed:
            by_verdict.setdefault(finding.verdict, []).append(finding)

    out: list[str] = []
    out.append("## Dependency Risk Report")
    out.append("")
    out.append(f"{total} packages · {direct} direct · from {src}")
    out.append("")
    counts = [
        ("act on", len(by_verdict.get(Verdict.ACT, []))),
        ("watch", len(by_verdict.get(Verdict.WATCH, []))),
        ("low", len(by_verdict.get(Verdict.LOW, []))),
        ("unknown", len(by_verdict.get(Verdict.UNKNOWN, []))),
        ("ok", len(by_verdict.get(Verdict.OK, []))),
    ]
    if accepted:
        counts.append(("accepted", len(accepted)))
    out.append("**" + " · ".join(f"{n} {label}" for label, n in counts) + "**")
    out.append("")
    pin_note = _pin_note(findings)
    if pin_note:
        for line in pin_note[0].split("\n"):
            out.append(f"> {_md_cell(line)}")
        out.append("")

    shown = 0
    for verdict, title, hint, _style in SECTIONS:
        group = sorted(by_verdict.get(verdict, []), key=_sort_key)
        if not group:
            continue
        shown += len(group)
        out.append(f"### {title.title()} — {hint}")
        out.append("")
        out.append("| Package | Version | Exposure | Why |")
        out.append("| --- | --- | --- | --- |")
        for finding in group:
            exposure = finding.exposure.label
            if finding.exposure.confidence is Confidence.INFERRED and finding.exposure.is_exposed:
                exposure += "?"
            why = [r.claim for r in finding.reasons] or ["-"]
            if finding.accepted is not None and finding.acceptance_expired:
                why.append(
                    f"acceptance {_until(finding, now)}: {finding.accepted.reason}"
                )
            # Joined after cleaning: clean() strips newlines with the rest of
            # the control characters, so a break has to be added afterwards.
            out.append(
                f"| `{_md_cell(finding.package.name)}` | {_md_cell(_version(finding))} "
                f"| {_md_cell(exposure)} | {'<br>'.join(_md_cell(w) for w in why)} |"
            )
        out.append("")

    if accepted:
        out.append("### Accepted Risk — on the record, not failing the build")
        out.append("")
        out.append("| Package | Version | Verdict | Reason | Until |")
        out.append("| --- | --- | --- | --- | --- |")
        labels = {v: hint for v, _, hint, _ in SECTIONS}
        for finding in sorted(accepted, key=_sort_key):
            assert finding.accepted is not None
            out.append(
                f"| `{_md_cell(finding.package.name)}` | {_md_cell(_version(finding))} "
                f"| {_md_cell(labels.get(finding.verdict, finding.verdict.value))} "
                f"| {_md_cell(finding.accepted.reason)} "
                f"| {_md_cell(_until(finding, now))} |"
            )
        out.append("")

    if not shown:
        out.append("Nothing to act on.")
        out.append("")
    note = describe_degraded(degraded)
    if note:
        out.append(f"> ⚠ {_md_cell(note)}")
        out.append("")
    for line in notes:
        out.append(f"> {_md_cell(line)}")
    if notes:
        out.append("")
    out.append("<sub>package-doctor explain &lt;name&gt; for the evidence behind a row</sub>")
    out.append("")
    return "\n".join(out)


def render_explain(console: Console, finding: Finding, exposure_note: str = "") -> None:
    pkg = finding.package
    rem = finding.remediation
    adv = rem.advisories

    console.print()
    title = Text(clean(f"{pkg.name} {pkg.version or ''}").strip(), style="bold")
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
        line.append(clean(value), style=value_style)
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
    if finding.exposure.consequence:
        row("Consequence", finding.exposure.consequence)
    if finding.exposure.why:
        row("Why", finding.exposure.why)
    row("Dependency", "direct" if pkg.direct else "transitive")
    if pkg.origins:
        row("Declared in", ", ".join(sorted(pkg.origins)))

    section("Reachability")
    if pkg.import_sites:
        where = " (test code only)" if pkg.imported_in_tests_only else ""
        row("Imported by your code", "yes" + where)
        for site in pkg.import_sites[:6]:
            console.print(Text(f"    {clean(site)}", style="dim"))
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
        "archived"
        if rem.repo_archived
        else ("active" if rem.repo_archived is False else "unknown"),
        "red" if rem.repo_archived else "",
    )
    if rem.repo_last_push:
        row("Last commit", rem.repo_last_push.date().isoformat())
    if rem.inactive_classifier:
        row("PyPI status", "Development Status :: 7 - Inactive", "red")
    if rem.open_issues is not None:
        row("Open issues", str(rem.open_issues))

    if finding.accepted is not None:
        section("Accepted risk")
        row(
            "Reason",
            finding.accepted.reason,
            "yellow" if finding.acceptance_expired else "",
        )
        row(
            "Expired" if finding.acceptance_expired else "Until",
            finding.accepted.until.isoformat(),
            "yellow" if finding.acceptance_expired else "",
        )
        row("Declared in", finding.accepted.source)
        if finding.acceptance_expired:
            console.print(
                Text("    This acceptance has run out and no longer suppresses "
                     "the finding.", style="dim")
            )

    section("Security track record")
    if pkg.version_assumed:
        row("Your version", f"{pkg.version} (assumed)", "yellow")
        console.print(
            Text(
                "    Nothing pins this package, so advisories were matched against\n"
                "    the newest release a fresh install would get. Pin it to be sure.",
                style="dim",
            )
        )
    if pkg.version is None:
        # Advisory matching needs a version, and without one this section
        # would silently be about the project's history rather than the
        # reader's install. Say what was not checked, and how to check it.
        row("Your version", "unknown - advisory matching skipped", "yellow")
        console.print(
            Text(
                "    Pass --pin VERSION, or run this inside the project so it can\n"
                "    be read from the lockfile.",
                style="dim",
            )
        )
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
                + (
                    f" (median {adv.median_late_days:.0f}d exposed)"
                    if adv.median_late_days
                    else ""
                ),
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
        if adv.bounded:
            row("Closed, no fix named", str(adv.bounded), "dim")
            console.print(
                Text(
                    "    The affected range ends before the latest release, so it is\n"
                    "    closed for current versions, but no fix date can be placed.",
                    style="dim",
                )
            )
        if adv.unmatched:
            row("Not datable", str(adv.unmatched), "dim")

    exploit = rem.exploitability
    if exploit.checked:
        section("Exploitability of your version")
        if exploit.kev:
            row("Known exploited (CISA)", ", ".join(exploit.kev), "bold red")
        kev_set = set(exploit.kev)
        for cve, score in exploit.scored[:5]:
            style = "bold red" if cve in kev_set else ("yellow" if score >= 0.10 else "")
            # Never round up to a flat 100%: EPSS tops out just short of 1.0 and
            # printing certainty the model does not claim is its own small lie.
            pct = ">99%" if score >= 0.995 else f"{score:.1%}"
            label = f"{pct} chance of exploitation in 30 days"
            row(cve, label, style)
        if len(exploit.scored) > 5:
            console.print(Text(f"    (+{len(exploit.scored) - 5} more scored)", style="dim"))
        if exploit.unscored:
            row("No EPSS score", f"{exploit.unscored} of {exploit.queried}", "dim")
            console.print(
                Text("    Unscored means unknown, not low risk.", style="dim")
            )

    if rem.gaps:
        section("Missing signals")
        for gap in rem.gaps:
            console.print(Text(f"  {clean(gap)}", style="dim"))

    if finding.reasons:
        section("Why this verdict")
        for reason in finding.reasons:
            line = Text("  • ")
            line.append(clean(reason.claim))
            console.print(line)
            if reason.url:
                console.print(Text(f"    {clean(reason.url)}", style="dim blue"))

    section("Evidence")
    console.print(Text(f"  https://pypi.org/project/{clean(pkg.name)}/", style="dim blue"))
    if rem.repo_url:
        console.print(Text(f"  {clean(rem.repo_url)}", style="dim blue"))
    if adv.has_signal:
        console.print(
            Text(f"  https://osv.dev/list?q={clean(pkg.name)}&ecosystem=PyPI", style="dim blue")
        )
    console.print()


def to_dict(
    findings: list[Finding],
    sources: Iterable[str],
    now: dt.datetime,
    degraded: dict[str, int] | None = None,
) -> dict[str, Any]:
    def serialise(finding: Finding) -> dict[str, Any]:
        rem = finding.remediation
        return {
            "name": finding.package.name,
            "version": finding.package.version,
            # True when "version" was not pinned but assumed from PyPI. Every
            # advisory match below is then a claim about that assumption.
            "version_assumed": finding.package.version_assumed,
            "specifier": finding.package.specifier,
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
                "why": finding.exposure.why,
                "consequence": finding.exposure.consequence,
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
                "exploitability": {
                    "checked": rem.exploitability.checked,
                    "known_exploited": rem.exploitability.kev,
                    "epss": [
                        {"cve": c, "score": s} for c, s in rem.exploitability.scored
                    ],
                    "queried": rem.exploitability.queried,
                    "unscored": rem.exploitability.unscored,
                },
                "missing_signals": rem.gaps,
            },
            "reasons": [{"claim": r.claim, "url": r.url} for r in finding.reasons],
            "error": finding.error,
            "accepted": (
                {
                    "reason": finding.accepted.reason,
                    "until": finding.accepted.until.isoformat(),
                    "version": finding.accepted.version,
                    "source": finding.accepted.source,
                    "expired": finding.acceptance_expired,
                    # The one consumers should key on: True means this
                    # finding did not count toward the exit code.
                    "suppressed": finding.suppressed,
                }
                if finding.accepted is not None
                else None
            ),
        }

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict.value] = counts.get(finding.verdict.value, 0) + 1

    return {
        "tool": "package-doctor",
        # 2: "version" may be assumed (see "version_assumed"), and findings
        # carry "accepted". Counts are still by verdict; "accepted" is the
        # number of findings an unexpired acceptance kept out of the exit code.
        "schema_version": 2,
        "generated_at": now.isoformat(),
        "sources": list(sources),
        "counts": counts,
        "accepted": sum(1 for f in findings if f.suppressed),
        "unpinned": sum(1 for f in findings if not f.package.version),
        "assumed": sum(1 for f in findings if f.package.version_assumed),
        # host -> requests that failed after retries. Non-empty means some
        # gaps below are the upstream's doing rather than the package's.
        "degraded": dict(degraded or {}),
        "findings": [serialise(f) for f in findings],
    }
