"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from rich.console import Console
from rich.markup import escape

from . import __version__
from .accept import CONFIG_NAME, Acceptances, ConfigError, apply_acceptances, load_acceptances
from .analysis import Analyzer
from .cache import Cache, default_cache_path
from .exposure import load_exposure_map
from .guard import (
    BLOCK,
    NEW_DAYS,
    UNCHECKED,
    WARN,
    Decision,
    Provenance,
    added_requirements,
    decide,
    index_uses,
    is_remote_install_target,
    load_popular,
    parse_install_command,
    parse_requirement,
    resolved_additions,
    unresolvable_install_targets,
    writes_lockfile,
)
from .hooks import PROTOCOLS, SILENT, HookEvent, HookResult
from .models import Exposure, Finding, Package, Remediation, Verdict
from .parsers import collect_dependencies
from .parsers.discovery import (
    MAX_MANIFEST_BYTES,
    NESTED_DEPTH,
    discover_project,
    is_dependency_file,
)
from .report import (
    describe_degraded,
    describe_not_analysed,
    render,
    render_explain,
    render_markdown,
    to_dict,
)
from .risk import Thresholds, assess
from .sarif import to_sarif
from .sources.client import Client
from .sources.pypi import normalise
from .sourcescan import (
    MAX_FILE_BYTES,
    build_index,
    detect_source_roots,
    merge_sites,
    prune_nested_roots,
)

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

#: What each --fail-on level counts as a failure. The default keys off
#: `Finding.blocks`: active exploitation anywhere, and a replacement or upgrade
#: at a reviewed trust boundary. The stricter levels ignore the boundary.
_FAIL_LEVELS: dict[str, Callable[[Finding], bool]] = {
    "never": lambda f: False,
    "exploited": lambda f: f.verdict is Verdict.EXPLOITED,
    "boundary": lambda f: f.blocks,
    "vulnerable": lambda f: f.verdict in (
        Verdict.EXPLOITED, Verdict.REPLACE, Verdict.MITIGATE, Verdict.UPGRADE
    ),
    "all": lambda f: f.verdict not in (Verdict.OK, Verdict.UNCHECKED),
}

#: Fails on what a reviewed boundary says is not optional, and nothing else.
DEFAULT_FAIL_LEVEL = "boundary"

#: Level names from before the groups existed, kept so an existing pipeline
#: does not break on an unknown choice.
_FAIL_ALIASES = {
    "act": "boundary", "watch": "vulnerable", "replace": "boundary",
    "upgrade": "boundary", "review": "vulnerable", "bump": "vulnerable",
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _display(path: Path, root: Path) -> str:
    """A file as the user would name it: relative to the project when inside it."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _depth(value: str) -> int:
    """argparse type for --depth: a non-negative directory count.

    A negative value would just make discover_nested's `range(depth)` loop
    run zero times - the same as 0 - which is a confusing way to fail. Reject
    it explicitly instead.
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if n < 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be 0 or greater")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="package-doctor",
        description=(
            "Find which Python dependencies to fix first: the ones being exploited, "
            "and the ones nobody is left to patch."
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
            "--stale-release-days", type=int, default=Thresholds.stale_release_days,
            help="days without a release that count as one weak signal (default: "
                 f"{Thresholds.stale_release_days})",
        )
        p.add_argument(
            "--stale-push-days", type=int, default=Thresholds.stale_push_days,
            help="days without a pushed commit that count as one weak signal (default: "
                 f"{Thresholds.stale_push_days})",
        )
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
    scan.add_argument(
        "--depth",
        type=_depth,
        default=NESTED_DEPTH,
        metavar="N",
        help=(
            "how many directories below the root to look for dependency "
            f"files, when the root itself declares none (default: {NESTED_DEPTH})"
        ),
    )
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
        "--all",
        dest="show_all",
        action="store_true",
        help="list the groups away from a reviewed trust boundary, instead of a count",
    )
    scan.add_argument(
        "--fail-on",
        choices=[*_FAIL_LEVELS, *_FAIL_ALIASES],
        default=DEFAULT_FAIL_LEVEL,
        metavar="{exploited,boundary,vulnerable,all,never}",
        help=f"exit non-zero at this level or worse (default: {DEFAULT_FAIL_LEVEL})",
    )
    common(scan)

    explain = sub.add_parser("explain", help="show the evidence behind one package")
    explain.add_argument(
        "name", help="a name, or a pinned requirement like pillow==10.0.0 (same as --pin)"
    )
    explain.add_argument(
        "--pin",
        metavar="VERSION",
        help="the version you depend on, for advisory matching (default: read from the lockfile)",
    )
    explain.add_argument(
        "--path", default=".", help="project directory to check for imports (default: .)"
    )
    explain.add_argument(
        "--depth",
        type=_depth,
        default=NESTED_DEPTH,
        metavar="N",
        help=(
            "how many directories below --path to look for dependency "
            f"files, when the root itself declares none (default: {NESTED_DEPTH})"
        ),
    )
    explain.add_argument(
        "--src",
        type=Path,
        action="append",
        metavar="PATH",
        help="source directory or file to check for imports (repeatable; default: auto-detect)",
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
    check.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help=f"accepted-risk file (default: {CONFIG_NAME} in the current directory, "
             f"or [tool.package-doctor] in pyproject.toml)",
    )
    common(check)

    hook = sub.add_parser(
        "hook",
        help="run as a coding-agent hook: read the tool call from stdin, check what it installs",
    )
    hook.add_argument("agent", choices=sorted(PROTOCOLS), help="which agent's hook protocol")
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
        # Nothing declared at the root: look a little way down, skipping the
        # places where somebody else's dependency files live.
        root = target
        paths, nested = discover_project(target, depth=args.depth)
        if nested:
            shown = ", ".join(_display(p, root) for p in nested[:4])
            more = f" and {len(nested) - 4} more" if len(nested) > 4 else ""
            lead = (
                "No dependency files at the root; using"
                if paths == nested
                else "Nothing at the root declares a dependency; also using"
            )
            notes.print(
                f"[dim]{lead} {shown}{more}, found up to {args.depth} "
                f"directories down.[/dim]"
            )
    else:
        console.print(f"[red]No such file or directory:[/red] {escape(str(target))}")
        return EXIT_USAGE

    if not paths:
        console.print(f"[yellow]No dependency files found in[/yellow] {escape(str(root))}")
        console.print(
            "[dim]Looked for: uv.lock, poetry.lock, Pipfile.lock, pyproject.toml, "
            "Pipfile, setup.cfg, setup.py, requirements*.txt - at the root and up to "
            f"{args.depth} directories down, outside tests, docs, examples and "
            "vendored code.[/dim]"
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
    for unread, reason in deps.unread:
        notes.print(
            f"[yellow]Not fully read:[/yellow] {escape(_display(unread, root))} - "
            f"{escape(reason)}, so its dependencies are not in this scan. setup.py is "
            f"parsed, never run."
        )
    if deps.other_versions:
        # One version is scanned; the others still install somewhere, or are
        # pinned somewhere, so they are named here instead of disappearing.
        forks = sorted(deps.other_versions.items())
        shown = "; ".join(
            f"{name} {deps.versions[name]} (also {', '.join(sorted(others))})"
            for name, others in forks[:4]
        )
        more = f"; and {len(forks) - 4} more" if len(forks) > 4 else ""
        notes.print(
            f"[yellow]Pinned at more than one version:[/yellow] {escape(shown + more)}. "
            f"Scanned the lockfile's version, else the newest; the others are locked "
            f"for some Python versions or extras, or pinned in another file. Check "
            f"one with explain --pin."
        )
    if not deps:
        notes.print("[yellow]No dependencies found.[/yellow]")
        # A pipeline that asked for a report still gets one, empty, with the
        # files it could not read: huggingface/transformers exited 0 and wrote
        # no file, so the step reading the JSON failed on a missing path.
        if not (args.as_json or args.output or args.sarif or args.markdown):
            return EXIT_OK

    # Reachability: which of these the project's own code actually imports.
    # Positive evidence only - see sourcescan for why absence proves nothing.
    index = None
    if not args.no_reachability and deps:
        requested = [Path(p).expanduser().resolve() for p in (args.src or [])]
        for missing in requested:
            if not (missing.is_dir() or missing.is_file()):
                notes.print(
                    f"[yellow]No such file or directory, skipping:[/yellow] "
                    f"{escape(str(missing))}"
                )
        requested = [p for p in requested if p.is_dir() or p.is_file()]
        # Only the outermost roots are walked: a file under two of them was
        # indexed and reported twice.
        roots = prune_nested_roots(requested) if args.src else detect_source_roots(root)
        known = set(deps.versions)
        merged: dict[str, list] = {}
        scanned = 0
        for src_root in roots:
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
                merged.setdefault(dist, []).append(sites)
        if scanned:
            index = {dist: merge_sites(parts) for dist, parts in merged.items()}

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
        findings, source_names, now, degraded=degraded, not_analysed=deps.not_analysed,
        unread=[(_display(p, root), reason) for p, reason in deps.unread],
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
            console, findings, sources=source_names, show_ok=args.show_ok,
            show_all=args.show_all, now=now,
            degraded=degraded, notes=acceptance_notes,
        )

    fails = _FAIL_LEVELS[_FAIL_ALIASES.get(args.fail_on, args.fail_on)]
    if any(fails(f) and not f.suppressed for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


async def _run_explain(args: argparse.Namespace, console: Console) -> int:
    # `explain bleach==6.4.0` is how pip spells it, so take it. Queried as-is,
    # the whole string went to PyPI as a name and came back "not found".
    try:
        name, pinned, specifier = parse_requirement(args.name)
    except InvalidRequirement as exc:
        console.print(f"[red]Not a package name or requirement:[/red] {escape(str(exc))}")
        return EXIT_USAGE
    if pinned and args.pin and pinned != args.pin:
        console.print(
            f"[red]Two versions given:[/red] {escape(args.name)} and --pin "
            f"{escape(args.pin)}. Pass one."
        )
        return EXIT_USAGE
    pin = args.pin or pinned

    now = _now()
    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    exposure_map = load_exposure_map()
    package = Package(name=name, version=pin, specifier=None if pin else specifier, direct=True)

    # Reachability is most useful exactly here, so check it when `explain` is
    # run inside a project rather than making the user go back to `scan`.
    root = Path(args.path).expanduser().resolve()
    acceptances = None
    if not args.no_reachability and root.is_dir():
        version_from_lock = None
        try:
            manifests, _ = discover_project(root, depth=args.depth)
            deps = collect_dependencies(manifests, root=root)
            version_from_lock = deps.versions.get(normalise(name))
            known = set(deps.versions)
            if pin is None and not version_from_lock and not specifier:
                package.specifier = deps.specifiers.get(normalise(name))
        except Exception:
            known = set()
        if pin is None and version_from_lock:
            package.version = version_from_lock
        try:
            acceptances = load_acceptances(root, None)
        except ConfigError as exc:
            console.print(f"[yellow]Accepted risks not read:[/yellow] {escape(str(exc))}")
        if args.src:
            requested = [Path(p).expanduser().resolve() for p in args.src]
            for missing in requested:
                if not (missing.is_dir() or missing.is_file()):
                    console.print(
                        f"[yellow]No such file or directory, skipping:[/yellow] "
                        f"{escape(str(missing))}"
                    )
            roots = prune_nested_roots([p for p in requested if p.is_dir() or p.is_file()])
        else:
            roots = detect_source_roots(root)
        parts: list[list] = []
        for src_root in roots:
            try:
                parts.append(
                    build_index(src_root, known_packages=known, display_root=root)
                    .for_package(name)
                )
            except Exception:
                continue
        sites = merge_sites(parts)
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
    fails = _FAIL_LEVELS[DEFAULT_FAIL_LEVEL]
    return EXIT_FINDINGS if fails(finding) and not finding.suppressed else EXIT_OK


CheckRow = tuple[Package, Finding, Decision]


def _direct_reference_url(text: str) -> str | None:
    """The URL or VCS target of a PEP 508 direct reference requirement -
    ``name @ https://...`` or ``name @ git+https://...`` - if this is one.

    ``parse_requirement`` reports only the name for these, which on its own
    would make ``package-doctor check "requests @ https://evil.example/x.whl"``
    show a clean check of the real PyPI ``requests``: right name, wrong
    artifact. What ``pip install`` actually fetches for a direct reference is
    whatever sits at the URL, which has no necessary relationship to the PyPI
    project of the same name and carries no registry or advisory history to
    check it against.
    """
    try:
        return Requirement(text).url
    except InvalidRequirement:
        return None


async def run_check(
    requirements: list[str], *, args: argparse.Namespace,
    acceptances: Acceptances | None = None,
) -> tuple[list[CheckRow], dict[str, int]]:
    """Look up each requirement and decide. Shared by `check` and the hook.

    Accepted risks apply exactly as they do in `scan`, so an entry that keeps
    a package from failing CI also lets the agent install it.
    """
    now = _now()
    to_analyze: list[tuple[int, Package]] = []
    direct_refs: dict[int, tuple[Package, str]] = {}
    for i, text in enumerate(requirements):
        name, pinned, specifier = parse_requirement(text)
        package = Package(name=name, version=pinned, specifier=specifier, direct=True)
        url = _direct_reference_url(text)
        if url:
            direct_refs[i] = (package, url)
        else:
            to_analyze.append((i, package))

    degraded: dict[str, int] = {}
    findings_by_index: dict[int, Finding] = {}
    if to_analyze:
        cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
        try:
            async with Client(cache, concurrency=args.concurrency) as client:
                analyzer = Analyzer(
                    client, load_exposure_map(), _thresholds(args), skip_repo=args.offline_repo,
                    assume_latest=args.assume_latest,
                )
                findings = await analyzer.analyze_all([p for _, p in to_analyze], now)
                degraded = dict(client.degraded)
        finally:
            cache.close()
        if acceptances is not None and acceptances.entries:
            apply_acceptances(findings, acceptances, now)
        for (i, _), finding in zip(to_analyze, findings, strict=True):
            findings_by_index[i] = finding

    popular = load_popular()
    computed: dict[int, CheckRow] = {}
    for i, package in to_analyze:
        decision = decide(
            findings_by_index[i], now=now, popular=popular, new_days=args.new_days,
            degraded=bool(degraded),
        )
        computed[i] = (package, findings_by_index[i], decision)
    for i, (package, url) in direct_refs.items():
        # decide()'s generic "finding.error is set" path reports UNCHECKED
        # and allows the install - correct for an upstream outage, backwards
        # here: an uncheckable *URL* install, fetching code with no registry
        # entry at all, is exactly the case this guardrail exists for. Built
        # directly instead, rather than routed through decide().
        finding = assess(
            package, Exposure(), Remediation(gaps=[f"direct URL/VCS reference: {url}"]),
            now=now, thresholds=_thresholds(args),
        )
        finding.error = f"direct URL/VCS reference, not a PyPI lookup: {url}"
        computed[i] = (
            package,
            finding,
            Decision(
                BLOCK,
                [f"installs directly from {url}, not from PyPI - no registry, "
                 f"advisory or provenance check applies to this; review the "
                 f"source before allowing it"],
                Provenance(found=None),
            ),
        )
    return [computed[i] for i in range(len(requirements))], degraded


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
                "accepted": (
                    {
                        "reason": f.accepted.reason,
                        "until": f.accepted.until.isoformat(),
                        "source": f.accepted.source,
                        "expired": f.acceptance_expired,
                    }
                    if f.accepted is not None else None
                ),
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

    try:
        acceptances = load_acceptances(Path.cwd(), args.config)
    except ConfigError as exc:
        console.print(f"[red]Cannot read accepted risks:[/red] {escape(str(exc))}")
        return EXIT_USAGE
    rows, degraded = await run_check(args.requirements, args=args, acceptances=acceptances)
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


#: How long a session's record of what it has already been told is kept.
_SESSION_TTL = 7 * 24 * 3600


def _session_file(session: str) -> Path | None:
    if not session:
        return None
    digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:16]
    return default_cache_path().parent / "hook-sessions" / f"{digest}.json"


def _unseen(session: str, keys: list[str]) -> list[str]:
    """The keys this session has not already been told about, recording them.

    An agent that retries the same install gets the same paragraph again, and
    repeated context is what teaches a model to skim it. Only warnings are
    deduplicated: a block is a refusal, and a refusal has to be repeated every
    time the command is tried. Any failure to read or write the record returns
    everything, because a lost warning is worse than a duplicated one.
    """
    path = _session_file(session)
    if path is None:
        return keys
    try:
        seen = set(json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else set()
    except (OSError, ValueError):
        seen = set()
    fresh = [key for key in keys if key not in seen]
    if not fresh:
        return []
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sorted(seen | set(keys))), encoding="utf-8")
        cutoff = _now().timestamp() - _SESSION_TTL
        for old in path.parent.glob("*.json"):
            if old.stat().st_mtime < cutoff:
                old.unlink(missing_ok=True)
    except OSError:
        pass
    return fresh


def _row_key(row: CheckRow) -> str:
    package, _finding, decision = row
    return f"{decision.level}:{package.name}:{package.version or ''}"


def _hook_acceptances(root: Path) -> Acceptances | None:
    """The project's accepted risks, for a hook.

    `scan` treats a malformed file as a usage error. A hook cannot stop to ask,
    so it reads nothing instead: every finding is then unaccepted, which can
    only block more than intended, never less.
    """
    try:
        return load_acceptances(root)
    except (ConfigError, OSError):
        return None


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
    """Run as a coding agent's hook.

    Reads the tool call from stdin in the agent's own format, decides, and
    answers in the same format; `hooks` holds the translation for each agent.
    A block stops the call and puts the reasons in front of the model, which
    is what makes an agent pick a different package rather than retry the
    same one. Anything short of a block leaves the agent's normal permission
    flow untouched: a warning is attached as context, never as an automatic
    "allow", so the hook can never widen what the agent was already
    permitted to run.

    Everything that is not a decision about a package - malformed input, a
    tool that runs nothing, a command that installs nothing, an exception in
    the lookup - is silent. A guardrail that stops work when it cannot
    answer is the first thing a team removes.
    """
    protocol = PROTOCOLS[args.agent]
    try:
        payload = json.loads(stdin) if stdin.strip() else {}
    except json.JSONDecodeError:
        return EXIT_OK
    if not isinstance(payload, dict):
        return EXIT_OK
    event = protocol.parse(payload)
    if event is None:
        return EXIT_OK
    if event.kind == "edit":
        result = await _hook_edit(args, event)
    elif event.kind == "resolve":
        result = await _hook_resolve(args, event)
    else:
        result = await _hook_install(args, event)
    reply = protocol.render(event, result)
    if reply.stdout:
        sys.stdout.write(reply.stdout)
    if reply.stderr:
        sys.stderr.write(reply.stderr)
    return reply.code


async def _hook_install(args: argparse.Namespace, event: HookEvent) -> HookResult:
    """Before a shell command runs: check what it would install."""
    command = event.command
    requirements = parse_install_command(command)
    # Anything the shell parser recognised as an install target but could
    # not turn into a checkable name - a URL or a VCS reference, the
    # highest-risk form of install there is. Checked unconditionally, not
    # only when `requirements` is empty: `pip install requests
    # https://evil.example/pkg.whl` must not slip through just because
    # `requests` also appears in the same command.
    remote = [
        target for target in unresolvable_install_targets(command)
        if is_remote_install_target(target)
    ]
    if not requirements and not remote:
        return SILENT

    rows: list[CheckRow] = []
    unchecked: str | None = None
    if requirements:
        try:
            rows, _degraded = await run_check(
                requirements, args=args,
                acceptances=_hook_acceptances(event.cwd or Path.cwd()),
            )
        except Exception as exc:  # fail open, and say so where the user can see it
            if not remote:
                return HookResult(
                    notice=f"package-doctor could not check this install ({exc}); "
                           f"it was allowed unchecked.",
                )
            # Failing open is for outages: the registry could not answer about
            # a *name*, so the name is allowed rather than stopping work on
            # somebody else's downtime. A URL or VCS target in the same command
            # never needed a registry answer to be blocked, and a lookup error
            # must not become the way past it - `pip install requests
            # https://evil.example/pkg.whl` during a PyPI outage is still a
            # URL install. The names are reported as unchecked; the block
            # below stands on the URL alone.
            unchecked = (
                "UNCHECKED " + ", ".join(requirements)
                + f": could not be checked ({exc}); allowed on its own, but this "
                  "command is blocked for the target below"
            )

    # Where this command would resolve from. "Not on PyPI" is only proof of an
    # invented name when PyPI is where the install would look: with a private
    # index configured, an unknown name is what an internal package looks like,
    # and blocking it teaches the team to remove the hook.
    indexes = index_uses(command)
    if indexes:
        for _package, _finding, decision in rows:
            if decision.level == BLOCK and decision.provenance.found is False:
                decision.level = WARN
                decision.reasons = [
                    f"not on PyPI, and this command resolves against {indexes[0].url}: "
                    f"it may be internal, or it may be a name that exists nowhere"
                ] + decision.reasons[1:]

    lines = _hook_lines(rows)
    if unchecked:
        lines.append(unchecked)
    if remote:
        lines.append(
            "BLOCK " + ", ".join(remote) + ": installs directly from a URL or VCS "
            "reference, not a PyPI package - no registry, advisory or provenance "
            "check applies to this"
        )

    blocking = {BLOCK, WARN} if args.warn_blocks else {BLOCK}
    if remote or any(d.level in blocking for _, _, d in rows):
        # A version that would pass, spelled as a command. Without it the model
        # has only a refusal, and the next thing it does is try again.
        remedies = [d.remedy for _, _, d in rows if d.remedy]
        retry = "".join(f"\n  -> retry with {r}" for r in remedies)
        return HookResult(block=(
            "package-doctor blocked this install:\n  " + "\n  ".join(lines) + retry
            + "\nPick a maintained alternative, pin a fixed version, or ask the user "
              "to add an acceptance to package-doctor.toml and rerun.\n"
        ))

    # Accepted risks are allowed, but said once: the agent should know it is
    # adding something the project has chosen to carry, and until when.
    context_rows = [
        row for row in rows if row[2].level in (WARN, UNCHECKED) or row[1].suppressed
    ]
    fresh = set(_unseen(event.session, [_row_key(row) for row in context_rows]))
    context_lines = _hook_lines([row for row in context_rows if _row_key(row) in fresh])
    context_lines += [
        f"NOTE {use.reason}" for use in indexes
        if _unseen(event.session, [f"index:{use.url}"])
    ]
    if not context_lines:
        return SILENT
    return HookResult(context="package-doctor: " + " | ".join(context_lines))


async def _hook_resolve(args: argparse.Namespace, event: HookEvent) -> HookResult:
    """After a shell command runs: check what it added to the lockfile.

    `uv sync` and friends name no package, so the install hook has nothing to
    read. `uv add requests` names one, and that name was checked before it ran
    - but everything it pulled in with it, dependencies of dependencies, only
    exists afterwards, in the lockfile. Both are handled the same way: the
    lockfile is diffed against the version git last committed, and what was
    added is checked, leaving out names the command typed because the install
    hook already spoke about those. It cannot block, because the packages are
    already installed; the finding goes to the model as context, which is what
    it needs to change course before anything runs the code.
    """
    command = event.command
    if not writes_lockfile(command):
        return SILENT
    root = event.cwd or Path.cwd()
    try:
        requirements, more = resolved_additions(root)
    except Exception:
        return SILENT
    typed = set()
    for text in parse_install_command(command):
        try:
            typed.add(normalise(parse_requirement(text)[0]))
        except InvalidRequirement:
            continue
    kept = []
    for text in requirements:
        try:
            if normalise(parse_requirement(text)[0]) in typed:
                continue
        except InvalidRequirement:
            pass
        kept.append(text)
    requirements = kept
    if not requirements:
        return SILENT
    try:
        rows, _degraded = await run_check(
            requirements, args=args, acceptances=_hook_acceptances(root),
        )
    except Exception:
        return SILENT
    flagged = [row for row in rows if row[2].level in (BLOCK, WARN)]
    fresh = set(_unseen(event.session, [_row_key(row) for row in flagged]))
    flagged = [row for row in flagged if _row_key(row) in fresh]
    if not flagged:
        return SILENT
    lines = _hook_lines(flagged)
    if more:
        lines.append(f"(+{more} more newly locked packages, not checked)")
    return HookResult(
        context="package-doctor checked what this command just added to the lockfile: "
                + " | ".join(lines),
    )


async def _hook_edit(args: argparse.Namespace, event: HookEvent) -> HookResult:
    """After a file is written: check what the edit added to a dependency file.

    An agent that writes a name into pyproject.toml and then runs `uv sync`
    never types the name into a shell command, so the install hook cannot
    see it. This one runs after the edit, reads the file from disk, and
    checks only the names the edit introduced. The edit has already
    happened, so nothing here can block: the finding goes to the model as
    context, which is enough for it to fix the file before anything
    resolves it. Silent on every edit that is not to a dependency file.

    One tool call can write several files - a Codex patch often touches
    pyproject.toml and a requirements file together - and they are checked
    as one list, so a name added to both is reported once.
    """
    if not event.paths:
        return SILENT
    root = event.cwd or event.paths[0].parent
    requirements: list[str] = []
    changed: list[str] = []
    for path in event.paths:
        try:
            added = added_requirements(path, root)
        except Exception:
            continue
        if added:
            changed.append(path.name)
            requirements += [text for text in added if text not in requirements]
    if not requirements:
        return SILENT
    files = ", ".join(changed)
    try:
        rows, _degraded = await run_check(
            requirements, args=args, acceptances=_hook_acceptances(root),
        )
    except Exception as exc:
        return HookResult(
            notice=f"package-doctor could not check the dependencies just added "
                   f"to {files} ({exc}).",
        )
    flagged = [(p, f, d) for p, f, d in rows if d.level in (BLOCK, WARN, UNCHECKED)]
    if not flagged:
        return SILENT
    lines = _hook_lines(flagged)
    blocked = any(d.level == BLOCK for _, _, d in flagged)
    advice = (
        "Remove the blocked package from the file before anything installs it, "
        "pick a maintained alternative, or ask the user to add an acceptance to "
        "package-doctor.toml."
        if blocked else "Worth a look before syncing."
    )
    return HookResult(
        context=f"package-doctor checked what was just added to {files}: "
                + " | ".join(lines) + f" {advice}",
    )


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
