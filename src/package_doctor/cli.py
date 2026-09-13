"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement
from rich.console import Console
from rich.markup import escape

from . import __version__
from .accept import CONFIG_NAME, ConfigError, apply_acceptances, load_acceptances
from .analysis import Analyzer
from .cache import Cache, default_cache_path
from .exposure import load_exposure_map
from .guard import (
    BLOCK,
    NEW_DAYS,
    UNCHECKED,
    WARN,
    Decision,
    added_requirements,
    decide,
    load_popular,
    parse_install_command,
    parse_requirement,
)
from .models import Finding, Package, Verdict
from .parsers import collect_dependencies, discover_manifests
from .parsers.discovery import MAX_MANIFEST_BYTES, is_dependency_file
from .report import (
    describe_degraded,
    describe_not_analysed,
    render,
    render_explain,
    render_markdown,
    to_dict,
)
from .risk import Thresholds
from .sarif import to_sarif
from .sources.client import Client
from .sources.pypi import normalise
from .sourcescan import MAX_FILE_BYTES, build_index, detect_source_roots

#: Refuse to look up more packages than this without being asked.
#:
#: Each package costs up to three requests to free, unauthenticated services.
#: A lockfile with a hundred thousand entries - which nothing stops a scanned
#: repository from containing - would fire a third of a million requests and
#: quite reasonably get the user's address blocked. The largest real project
#: tested here had 349 dependencies.
MAX_PACKAGES = 2000

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_FAIL_LEVELS = {
    "act": [Verdict.ACT],
    "watch": [Verdict.ACT, Verdict.WATCH],
    "never": [],
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _display(path: Path, root: Path) -> str:
    """A file as the user would name it: relative to the project when inside it."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="package-doctor",
        description=(
            "Find dependencies that sit at a trust boundary and have no one left to fix them."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--no-cache", action="store_true", help="bypass the local response cache")
        p.add_argument(
            "--cache-ttl", type=int, default=24 * 3600, help="cache lifetime in seconds"
        )
        p.add_argument(
            "--concurrency", type=int, default=8, help="parallel network requests (default: 8)"
        )
        p.add_argument(
            "--offline-repo",
            action="store_true",
            help="skip repository lookups (faster, fewer signals)",
        )
        p.add_argument(
            "--stale-release-days", type=int, default=Thresholds.stale_release_days
        )
        p.add_argument("--stale-push-days", type=int, default=Thresholds.stale_push_days)
        p.add_argument(
            "--no-assume-latest",
            dest="assume_latest",
            action="store_false",
            help=(
                "with no pinned version, skip advisory matching instead of assuming "
                "the newest release a fresh install would get"
            ),
        )

    scan = sub.add_parser("scan", help="scan a project's dependencies")
    scan.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    scan.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    scan.add_argument(
        "--output", "-o", type=Path, help="write JSON to a file instead of stdout"
    )
    scan.add_argument(
        "--sarif",
        type=Path,
        metavar="PATH",
        help="also write a SARIF 2.1.0 report here, for GitHub code scanning and similar",
    )
    scan.add_argument(
        "--markdown",
        type=Path,
        metavar="PATH",
        help="also write the report as Markdown here, e.g. a CI job's step summary",
    )
    scan.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help=f"accepted-risk file (default: {CONFIG_NAME} in the project, "
             f"or [tool.package-doctor] in pyproject.toml)",
    )
    scan.add_argument("--show-ok", action="store_true", help="also list packages with no concerns")
    scan.add_argument(
        "--direct-only", action="store_true", help="only scan dependencies you declared yourself"
    )
    scan.add_argument(
        "--max-packages",
        type=int,
        default=MAX_PACKAGES,
        help=f"refuse to look up more than this many packages (default {MAX_PACKAGES})",
    )
    scan.add_argument(
        "--src",
        type=Path,
        action="append",
        metavar="PATH",
        help="source directory to check for imports (repeatable; default: auto-detect)",
    )
    scan.add_argument(
        "--no-reachability",
        action="store_true",
        help="skip the import scan of your own source",
    )
    scan.add_argument(
        "--fail-on",
        choices=sorted(_FAIL_LEVELS),
        default="act",
        help="exit non-zero at this level or worse (default: act)",
    )
    common(scan)

    explain = sub.add_parser("explain", help="show the evidence behind one package")
    explain.add_argument("name", help="package name")
    explain.add_argument(
        "--pin",
        metavar="VERSION",
        help="the version you depend on, for advisory matching (default: read from the lockfile)",
    )
    explain.add_argument(
        "--path", default=".", help="project directory to check for imports (default: .)"
    )
    explain.add_argument(
        "--no-reachability", action="store_true", help="skip the import scan of your own source"
    )
    explain.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    common(explain)

    check = sub.add_parser(
        "check",
        help="decide whether packages are safe to add: block, warn or ok, one line each",
    )
    check.add_argument(
        "requirements", nargs="+", metavar="PACKAGE",
        help="a name, or a requirement like pillow==10.0.0 (unpinned means the newest release)",
    )
    check.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    check.add_argument(
        "--fail-on",
        choices=["block", "warn", "never"],
        default="block",
        help="exit non-zero at this level or worse (default: block)",
    )
    check.add_argument(
        "--new-days",
        type=int,
        default=NEW_DAYS,
        metavar="N",
        help=f"block a package first published within N days (default {NEW_DAYS})",
    )
    common(check)

    hook = sub.add_parser(
        "hook",
        help="run as a coding-agent hook: read the tool call from stdin, check what it installs",
    )
    hook.add_argument("agent", choices=["claude-code"], help="which agent's hook protocol")
    hook.add_argument(
        "--new-days", type=int, default=NEW_DAYS, metavar="N",
        help=f"block a package first published within N days (default {NEW_DAYS})",
    )
    hook.add_argument(
        "--warn-blocks", action="store_true",
        help="also block on warn-level results (default: warnings are passed to the agent)",
    )
    common(hook)

    cache_cmd = sub.add_parser("cache", help="inspect or clear the local cache")
    cache_cmd.add_argument("action", choices=["path", "clear"])

    return parser


def _thresholds(args: argparse.Namespace) -> Thresholds:
    return Thresholds(
        stale_release_days=args.stale_release_days,
        stale_push_days=args.stale_push_days,
    )


async def _run_scan(args: argparse.Namespace, console: Console) -> int:
    # With --json on stdout, stdout *is* the report and must parse. Notes
    # about skipped files and packages go to stderr in that mode, so a
    # pipeline reading the JSON never sees a stray line ahead of it.
    notes = Console(stderr=True) if args.as_json and not args.output else console
    target = Path(args.path).expanduser().resolve()
    if target.is_file():
        # A dependency file named directly: its directory is the project.
        if not is_dependency_file(target):
            console.print(
                f"[red]Not a dependency file I know how to read:[/red] {escape(str(target))}"
            )
            console.print(
                "[dim]Expected uv.lock, poetry.lock, Pipfile.lock, pyproject.toml, "
                "Pipfile or requirements*.txt[/dim]"
            )
            return EXIT_USAGE
        root, paths = target.parent, [target]
    elif target.is_dir():
        root, paths = target, discover_manifests(target)
    else:
        console.print(f"[red]No such file or directory:[/red] {escape(str(target))}")
        return EXIT_USAGE

    if not paths:
        console.print(f"[yellow]No dependency files found in[/yellow] {escape(str(root))}")
        console.print(
            "[dim]Looked for: uv.lock, poetry.lock, Pipfile.lock, pyproject.toml, "
            "Pipfile, requirements*.txt[/dim]"
        )
        return EXIT_USAGE

    deps = collect_dependencies(paths, root=root)
    for refused in deps.refused:
        notes.print(
            f"[yellow]Not read:[/yellow] {escape(_display(refused, root))} - larger than "
            f"{MAX_MANIFEST_BYTES // (1024 * 1024)}MB, outside the project, or not a "
            f"regular file. Its dependencies were not scanned."
        )
    if deps.local:
        shown = ", ".join(sorted(deps.local)[:4])
        more = f" and {len(deps.local) - 4} more" if len(deps.local) > 4 else ""
        notes.print(
            f"[dim]Skipped {shown}{more}: this project's own package"
            f"{'s' if len(deps.local) > 1 else ''}, not a dependency.[/dim]"
        )
    not_analysed = describe_not_analysed(deps.not_analysed)
    if not_analysed:
        notes.print(f"[yellow]{escape(not_analysed)}[/yellow]")
    if not deps:
        notes.print("[yellow]No dependencies found.[/yellow]")
        return EXIT_OK

    # Reachability: which of these the project's own code actually imports.
    # Positive evidence only - see sourcescan for why absence proves nothing.
    index = None
    if not args.no_reachability:
        roots = args.src or detect_source_roots(root)
        known = set(deps.versions)
        merged: dict[str, list] = {}
        scanned = 0
        for src_root in roots:
            src_root = Path(src_root).expanduser().resolve()
            if not (src_root.is_dir() or src_root.is_file()):
                notes.print(
                    f"[yellow]No such file or directory, skipping:[/yellow] "
                    f"{escape(str(src_root))}"
                )
                continue
            part = build_index(src_root, known_packages=known, display_root=root)
            scanned += part.files_scanned
            if part.files_too_large:
                notes.print(
                    f"[dim]Skipped {part.files_too_large} source file"
                    f"{'s' if part.files_too_large > 1 else ''} over "
                    f"{MAX_FILE_BYTES // (1024 * 1024)}MB; imports in them were "
                    f"not checked.[/dim]"
                )
            for dist, sites in part.sites.items():
                merged.setdefault(dist, []).extend(sites)
        if scanned:
            index = merged

    packages = []
    for name, version in sorted(deps.versions.items()):
        sites = (index or {}).get(name, [])
        packages.append(
            Package(
                name=name,
                version=version,
                specifier=deps.specifiers.get(name) if version is None else None,
                direct=name in deps.direct,
                origins=sorted(deps.origins.get(name, set())),
                import_sites=[str(s) for s in sites],
                imported_in_tests_only=bool(sites) and all(s.in_test for s in sites),
                reachability_checked=index is not None,
            )
        )
    if args.direct_only:
        packages = [p for p in packages if p.direct]

    if len(packages) > args.max_packages:
        notes.print(
            f"[yellow]{len(packages)} packages declared, which is more than the "
            f"{args.max_packages} this will look up.[/yellow]"
        )
        notes.print(
            "[dim]Each one costs requests to free, unauthenticated services. "
            "Use --max-packages to raise the limit, or --direct-only to scan "
            "just what you declared.[/dim]"
        )
        return EXIT_USAGE

    # Read before any network work: a malformed acceptance file is a usage
    # error, and the user should hear about it in a second, not a minute.
    try:
        acceptances = load_acceptances(root, args.config)
    except ConfigError as exc:
        console.print(f"[red]Cannot read accepted risks:[/red] {escape(str(exc))}")
        return EXIT_USAGE

    now = _now()
    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    exposure_map = load_exposure_map()

    try:
        async with Client(cache, concurrency=args.concurrency) as client:
            analyzer = Analyzer(
                client, exposure_map, _thresholds(args), skip_repo=args.offline_repo,
                assume_latest=args.assume_latest,
            )
            if args.as_json or args.output:
                findings = await analyzer.analyze_all(packages, now)
            else:
                with console.status(
                    f"[dim]Checking {len(packages)} packages…[/dim]", spinner="dots"
                ) as status:
                    done = 0

                    def tick() -> None:
                        nonlocal done
                        done += 1
                        status.update(f"[dim]Checking {len(packages)} packages… {done}[/dim]")

                    findings = await analyzer.analyze_all(packages, now, progress=tick)
            degraded = dict(client.degraded)
    finally:
        cache.close()

    acceptance_notes = apply_acceptances(findings, acceptances, now)

    source_names = [_display(p, root) for p in deps.sources]
    payload = to_dict(
        findings, source_names, now, degraded=degraded, not_analysed=deps.not_analysed
    )

    # The side outputs are written first, whatever the exit code turns out to
    # be: a CI step that fails on findings still needs the SARIF it uploads
    # and the summary it shows, and those are most useful exactly then.
    if args.sarif:
        args.sarif.write_text(
            json.dumps(to_sarif(findings, root, now), indent=2), encoding="utf-8"
        )
        notes.print(f"[dim]Wrote {escape(str(args.sarif))}[/dim]")
    if args.markdown:
        args.markdown.write_text(
            render_markdown(
                findings, sources=source_names, now=now, degraded=degraded,
                notes=[*([not_analysed] if not_analysed else []), *acceptance_notes],
            ),
            encoding="utf-8",
        )
        notes.print(f"[dim]Wrote {escape(str(args.markdown))}[/dim]")

    if args.output:
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[dim]Wrote {escape(str(args.output))}[/dim]")
    elif args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        render(
            console, findings, sources=source_names, show_ok=args.show_ok, now=now,
            degraded=degraded, notes=acceptance_notes,
        )

    failing = _FAIL_LEVELS[args.fail_on]
    if any(f.verdict in failing and not f.suppressed for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


async def _run_explain(args: argparse.Namespace, console: Console) -> int:
    now = _now()
    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    exposure_map = load_exposure_map()
    package = Package(name=args.name, version=args.pin, direct=True)

    # Reachability is most useful exactly here, so check it when `explain` is
    # run inside a project rather than making the user go back to `scan`.
    root = Path(args.path).expanduser().resolve()
    acceptances = None
    if not args.no_reachability and root.is_dir():
        version_from_lock = None
        try:
            deps = collect_dependencies(discover_manifests(root), root=root)
            version_from_lock = deps.versions.get(normalise(args.name))
            known = set(deps.versions)
            if args.pin is None and not version_from_lock:
                package.specifier = deps.specifiers.get(normalise(args.name))
        except Exception:
            known = set()
        if args.pin is None and version_from_lock:
            package.version = version_from_lock
        try:
            acceptances = load_acceptances(root, None)
        except ConfigError as exc:
            console.print(f"[yellow]Accepted risks not read:[/yellow] {escape(str(exc))}")
        sites: list = []
        for src_root in detect_source_roots(root):
            try:
                sites.extend(
                    build_index(src_root, known_packages=known, display_root=root)
                    .for_package(args.name)
                )
            except Exception:
                continue
        package.reachability_checked = True
        package.import_sites = [str(s) for s in sites]
        package.imported_in_tests_only = bool(sites) and all(s.in_test for s in sites)

    try:
        async with Client(cache, concurrency=args.concurrency) as client:
            analyzer = Analyzer(
                client, exposure_map, _thresholds(args), skip_repo=args.offline_repo,
                assume_latest=args.assume_latest,
            )
            finding = await analyzer.analyze(package, now)
            degraded = dict(client.degraded)
    finally:
        cache.close()
    if acceptances is not None:
        apply_acceptances([finding], acceptances, now)

    if args.as_json:
        print(json.dumps(to_dict([finding], [], now, degraded=degraded), indent=2))
        return EXIT_OK
    note = describe_degraded(degraded)
    if note:
        console.print(f"[yellow]{escape(note)}[/yellow]")

    note = ""
    if finding.exposure.categories:
        note = exposure_map.describe(finding.exposure.categories[0])
    render_explain(console, finding, exposure_note=note)
    return EXIT_FINDINGS if finding.verdict is Verdict.ACT and not finding.suppressed else EXIT_OK


CheckRow = tuple[Package, Finding, Decision]


async def run_check(
    requirements: list[str], *, args: argparse.Namespace
) -> tuple[list[CheckRow], dict[str, int]]:
    """Look up each requirement and decide. Shared by `check` and the hook."""
    packages = []
    for text in requirements:
        name, pinned, specifier = parse_requirement(text)
        packages.append(Package(name=name, version=pinned, specifier=specifier, direct=True))

    now = _now()
    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    try:
        async with Client(cache, concurrency=args.concurrency) as client:
            analyzer = Analyzer(
                client, load_exposure_map(), _thresholds(args), skip_repo=args.offline_repo,
                assume_latest=args.assume_latest,
            )
            findings = await analyzer.analyze_all(packages, now)
            degraded = dict(client.degraded)
    finally:
        cache.close()

    popular = load_popular()
    rows = []
    for package, finding in zip(packages, findings, strict=True):
        decision = decide(
            finding, now=now, popular=popular, new_days=args.new_days,
            degraded=bool(degraded),
        )
        rows.append((package, finding, decision))
    return rows, degraded


def check_payload(rows: list[CheckRow], degraded: dict[str, int], now: dt.datetime) -> dict:
    return {
        "tool": "package-doctor",
        "check_schema_version": 1,
        "generated_at": now.isoformat(),
        "degraded": degraded,
        "checks": [
            {
                "name": p.name,
                "version": p.version,
                "version_assumed": p.version_assumed,
                "verdict": f.verdict.value,
                "level": d.level,
                "reasons": d.reasons,
                "exposure": f.exposure.categories,
                "consequence": f.exposure.consequence,
                "provenance": {
                    "found": d.provenance.found,
                    "first_release": (
                        d.provenance.first_release.isoformat()
                        if d.provenance.first_release else None
                    ),
                    "days_since_first_release": d.provenance.days_since_first_release,
                    "near_miss": d.provenance.near_miss,
                },
            }
            for p, f, d in rows
        ],
    }


_CHECK_STYLE = {BLOCK: "bold red", WARN: "yellow", "ok": "green", UNCHECKED: "dim"}


def _check_exit(rows: list[CheckRow], fail_on: str) -> int:
    failing = {"block": {BLOCK}, "warn": {BLOCK, WARN}, "never": set()}[fail_on]
    return EXIT_FINDINGS if any(d.level in failing for _, _, d in rows) else EXIT_OK


async def _run_check(args: argparse.Namespace, console: Console) -> int:
    try:
        for text in args.requirements:
            parse_requirement(text)
    except InvalidRequirement as exc:
        console.print(f"[red]Not a requirement:[/red] {escape(str(exc))}")
        return EXIT_USAGE

    rows, degraded = await run_check(args.requirements, args=args)
    now = _now()
    if args.as_json:
        print(json.dumps(check_payload(rows, degraded, now), indent=2))
        return _check_exit(rows, args.fail_on)

    from rich.text import Text

    for package, _finding, decision in rows:
        line = Text()
        line.append(f"{decision.level.upper():<10}", style=_CHECK_STYLE[decision.level])
        version = package.version or ""
        if package.version_assumed:
            version += "?"
        line.append(f"{package.name} {version}".rstrip(), style="bold")
        line.append("\n")
        for reason in decision.reasons:
            line.append(f"          {reason}\n", style="dim" if decision.level == "ok" else "")
        console.print(line, end="")
    note = describe_degraded(degraded)
    if note:
        console.print(Text(note, style="yellow"))
    return _check_exit(rows, args.fail_on)


def _hook_lines(rows: list[CheckRow]) -> list[str]:
    out = []
    for package, _, decision in rows:
        version = f" {package.version}" if package.version else ""
        if package.version_assumed:
            version += " (newest release; nothing pinned it)"
        out.append(f"{decision.level.upper()} {package.name}{version}: "
                   + "; ".join(decision.reasons))
    return out


async def _run_hook(args: argparse.Namespace, stdin: str) -> int:
    """Claude Code PreToolUse hook.

    Reads the tool call from stdin. Exit 2 with the reasons on stderr blocks
    the call and puts the reasons in front of the model, which is what makes
    an agent pick a different package rather than retry the same one. Exit 0
    leaves the normal permission flow untouched: a warning is attached as
    context, never as an automatic "allow", so the hook can never widen what
    the agent was already permitted to run.

    Everything that is not a decision about a package - malformed input, a
    tool that is not Bash, a command that installs nothing, an exception in
    the lookup - exits 0 silently. A guardrail that stops work when it
    cannot answer is the first thing a team removes.
    """
    try:
        event = json.loads(stdin) if stdin.strip() else {}
    except json.JSONDecodeError:
        return EXIT_OK
    if not isinstance(event, dict):
        return EXIT_OK
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return EXIT_OK
    if tool in ("Edit", "Write", "MultiEdit"):
        return await _run_edit_hook(args, event, tool_input)
    if tool != "Bash":
        return EXIT_OK
    command = tool_input.get("command")
    if not isinstance(command, str):
        return EXIT_OK
    requirements = parse_install_command(command)
    if not requirements:
        return EXIT_OK

    try:
        rows, _degraded = await run_check(requirements, args=args)
    except Exception as exc:  # fail open, and say so where the user can see it
        print(json.dumps({
            "systemMessage": f"package-doctor could not check this install ({exc}); "
                             f"it was allowed unchecked.",
        }))
        return EXIT_OK

    lines = _hook_lines(rows)
    blocking = {BLOCK, WARN} if args.warn_blocks else {BLOCK}
    if any(d.level in blocking for _, _, d in rows):
        sys.stderr.write(
            "package-doctor blocked this install:\n  " + "\n  ".join(lines)
            + "\nPick a maintained alternative, pin a fixed version, or ask the user "
              "to add an acceptance to package-doctor.toml and rerun.\n"
        )
        return 2
    if any(d.level in (WARN, UNCHECKED) for _, _, d in rows):
        context = "package-doctor: " + " | ".join(lines)
        print(json.dumps({
            "systemMessage": context,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": context,
            },
        }))
    return EXIT_OK


async def _run_edit_hook(args: argparse.Namespace, event: dict, tool_input: dict) -> int:
    """Claude Code PostToolUse hook for edits to dependency files.

    An agent that writes a name into pyproject.toml and then runs `uv sync`
    never types the name into a shell command, so the install hook cannot
    see it. This one runs after the edit, reads the file from disk, and
    checks only the names the edit introduced. The edit has already
    happened, so nothing here can block: the finding goes to the model as
    context, which is enough for it to fix the file before anything
    resolves it. Silent on every edit that is not to a dependency file.
    """
    raw = tool_input.get("file_path")
    if not isinstance(raw, str) or not raw:
        return EXIT_OK
    path = Path(raw).expanduser()
    cwd = event.get("cwd")
    root = Path(cwd).expanduser() if isinstance(cwd, str) and cwd else path.parent
    try:
        requirements = added_requirements(path, root)
    except Exception:
        return EXIT_OK
    if not requirements:
        return EXIT_OK
    try:
        rows, _degraded = await run_check(requirements, args=args)
    except Exception as exc:
        print(json.dumps({
            "systemMessage": f"package-doctor could not check the dependencies just added "
                             f"to {path.name} ({exc}).",
        }))
        return EXIT_OK
    flagged = [(p, f, d) for p, f, d in rows if d.level in (BLOCK, WARN, UNCHECKED)]
    if not flagged:
        return EXIT_OK
    lines = _hook_lines(flagged)
    blocked = any(d.level == BLOCK for _, _, d in flagged)
    advice = (
        "Remove the blocked package from the file before anything installs it, "
        "pick a maintained alternative, or ask the user to add an acceptance to "
        "package-doctor.toml."
        if blocked else "Worth a look before syncing."
    )
    context = f"package-doctor checked what was just added to {path.name}: " \
              + " | ".join(lines) + f" {advice}"
    print(json.dumps({
        "systemMessage": context,
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": context,
        },
    }))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(stderr=False)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    if args.command == "cache":
        if args.action == "path":
            print(default_cache_path())
            return EXIT_OK
        cache = Cache()
        removed = cache.clear()
        cache.close()
        console.print(f"[dim]Cleared {removed} cached responses.[/dim]")
        return EXIT_OK

    try:
        if args.command == "scan":
            return asyncio.run(_run_scan(args, console))
        if args.command == "explain":
            return asyncio.run(_run_explain(args, console))
        if args.command == "check":
            return asyncio.run(_run_check(args, console))
        if args.command == "hook":
            return asyncio.run(_run_hook(args, sys.stdin.read()))
    except KeyboardInterrupt:
        console.print("[dim]Interrupted.[/dim]")
        return 130

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
