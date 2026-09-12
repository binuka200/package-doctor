"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from . import __version__
from .analysis import Analyzer
from .cache import Cache, default_cache_path
from .exposure import load_exposure_map
from .models import Package, Verdict
from .parsers import collect_dependencies, discover_manifests
from .parsers.discovery import MAX_MANIFEST_BYTES
from .report import render, render_explain, to_dict
from .risk import Thresholds
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

    scan = sub.add_parser("scan", help="scan a project's dependencies")
    scan.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    scan.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    scan.add_argument(
        "--output", "-o", type=Path, help="write JSON to a file instead of stdout"
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

    cache_cmd = sub.add_parser("cache", help="inspect or clear the local cache")
    cache_cmd.add_argument("action", choices=["path", "clear"])

    return parser


def _thresholds(args: argparse.Namespace) -> Thresholds:
    return Thresholds(
        stale_release_days=args.stale_release_days,
        stale_push_days=args.stale_push_days,
    )


async def _run_scan(args: argparse.Namespace, console: Console) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        console.print(f"[red]Not a directory:[/red] {escape(str(root))}")
        return EXIT_USAGE

    paths = discover_manifests(root)
    if not paths:
        console.print(f"[yellow]No dependency files found in[/yellow] {escape(str(root))}")
        console.print(
            "[dim]Looked for: uv.lock, poetry.lock, Pipfile.lock, pyproject.toml, "
            "Pipfile, requirements*.txt[/dim]"
        )
        return EXIT_USAGE

    deps = collect_dependencies(paths, root=root)
    for refused in deps.refused:
        console.print(
            f"[yellow]Not read:[/yellow] {escape(_display(refused, root))} - larger than "
            f"{MAX_MANIFEST_BYTES // (1024 * 1024)}MB, outside the project, or not a "
            f"regular file. Its dependencies were not scanned."
        )
    if deps.local:
        shown = ", ".join(sorted(deps.local)[:4])
        more = f" and {len(deps.local) - 4} more" if len(deps.local) > 4 else ""
        console.print(
            f"[dim]Skipped {shown}{more}: this project's own package"
            f"{'s' if len(deps.local) > 1 else ''}, not a dependency.[/dim]"
        )
    if not deps:
        console.print("[yellow]No dependencies found.[/yellow]")
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
            if not src_root.is_dir():
                console.print(
                    f"[yellow]Not a directory, skipping:[/yellow] {escape(str(src_root))}"
                )
                continue
            part = build_index(src_root, known_packages=known, display_root=root)
            scanned += part.files_scanned
            if part.files_too_large:
                console.print(
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
        console.print(
            f"[yellow]{len(packages)} packages declared, which is more than the "
            f"{args.max_packages} this will look up.[/yellow]"
        )
        console.print(
            "[dim]Each one costs requests to free, unauthenticated services. "
            "Use --max-packages to raise the limit, or --direct-only to scan "
            "just what you declared.[/dim]"
        )
        return EXIT_USAGE

    now = _now()
    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    exposure_map = load_exposure_map()

    try:
        async with Client(cache, concurrency=args.concurrency) as client:
            analyzer = Analyzer(
                client, exposure_map, _thresholds(args), skip_repo=args.offline_repo
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
    finally:
        cache.close()

    source_names = [_display(p, root) for p in deps.sources]
    payload = to_dict(findings, source_names, now)

    if args.output:
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[dim]Wrote {escape(str(args.output))}[/dim]")
    elif args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        render(console, findings, sources=source_names, show_ok=args.show_ok, now=now)

    failing = _FAIL_LEVELS[args.fail_on]
    if any(f.verdict in failing for f in findings):
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
    if not args.no_reachability and root.is_dir():
        version_from_lock = None
        try:
            deps = collect_dependencies(discover_manifests(root), root=root)
            version_from_lock = deps.versions.get(normalise(args.name))
            known = set(deps.versions)
        except Exception:
            known = set()
        if args.pin is None and version_from_lock:
            package.version = version_from_lock
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
                client, exposure_map, _thresholds(args), skip_repo=args.offline_repo
            )
            finding = await analyzer.analyze(package, now)
    finally:
        cache.close()

    if args.as_json:
        print(json.dumps(to_dict([finding], [], now), indent=2))
        return EXIT_OK

    note = ""
    if finding.exposure.categories:
        note = exposure_map.describe(finding.exposure.categories[0])
    render_explain(console, finding, exposure_note=note)
    return EXIT_FINDINGS if finding.verdict is Verdict.ACT else EXIT_OK


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
    except KeyboardInterrupt:
        console.print("[dim]Interrupted.[/dim]")
        return 130

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
