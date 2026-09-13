"""Find and parse dependency declarations.

Manifests tell us what a project asked for (its *direct* dependencies).
Lockfiles tell us what actually gets installed, transitives included - which is
where the neglected packages usually live. We read both and remember which
source each name came from, because "I never chose this" changes how a user
reacts to a finding.
"""

from __future__ import annotations

import configparser
import json
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from ..sources.pypi import normalise

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

MANIFESTS = ("pyproject.toml", "Pipfile", "setup.cfg")
LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock")

#: How far below the root the fallback search looks when the root itself has
#: no dependency files. Two levels reaches `configs/requirements.txt` and
#: `app/pyproject.toml`; it does not walk a monorepo.
NESTED_DEPTH = 2

#: Directories the fallback search never enters. The first group is never
#: the project's own code; the second is where somebody else's dependency
#: files live - a fixture with a requirements.txt is the reason discovery
#: was shallow to begin with.
NESTED_SKIP = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "site-packages", ".eggs", "htmlcov", ".idea", ".vscode",
    "tests", "test", "testing", "examples", "example", "docs", "doc",
    "fixtures", "fixture", "vendor", "vendored", "third_party", "third-party",
})
REQUIREMENTS_GLOB = "requirements*.txt"
#: The pip-tools and Django convention: one file per environment in a
#: directory, usually pulled in from a root requirements.txt with ``-r``.
REQUIREMENTS_DIR = "requirements"

#: How many ``-r`` includes deep a requirements file may reach. Real layouts
#: are one or two; a cycle or a chain past this is refused, not followed.
MAX_INCLUDE_DEPTH = 8

#: Largest dependency file we will read, in bytes.
#:
#: Lockfiles are read whole and handed to a TOML or JSON parser, so their size
#: is the memory the scan costs. The largest real one seen is a few megabytes;
#: this is generous enough for any monorepo and small enough that a checkout
#: cannot hand the scanner a multi-gigabyte file, or a symlink to one.
MAX_MANIFEST_BYTES = 32 * 1024 * 1024

#: PEP 503 normalised-name grammar. Anything outside it is not a package name.
_VALID_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

#: Not a package: Pipfile and some lockfiles record the interpreter itself
#: under this name. Everything else that appears in a dependency file is
#: analysed - including pip, setuptools and wheel, which used to be dropped
#: here without a word and have advisory histories of their own.
_IGNORED = {"python"}

#: Where a dependency comes from when it is not an index, for the report.
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


@dataclass
class DependencySet:
    #: normalised name -> pinned version (or None when only a range is known)
    versions: dict[str, str | None] = field(default_factory=dict)
    #: normalised name -> the declared range, for names with no exact pin.
    #: ``django<5`` installs the newest 4.x, not the newest release, and the
    #: assumed version has to respect that to be worth anything.
    specifiers: dict[str, str] = field(default_factory=dict)
    #: normalised names that appear in a manifest, i.e. deliberately chosen
    direct: set[str] = field(default_factory=set)
    #: normalised name -> files it was found in
    origins: dict[str, set[str]] = field(default_factory=dict)
    #: files we read, for reporting
    sources: list[Path] = field(default_factory=list)
    #: files we refused to read - too large, not a regular file, or an include
    #: that points outside the project - so the user can be told, because a
    #: skipped lockfile must not look like an empty one
    refused: list[Path] = field(default_factory=list)
    #: normalised names of packages that come from the project itself rather
    #: than from an index: the project's own distribution, workspace members,
    #: and anything a lockfile records with a local source. They have no PyPI
    #: history to judge and no maintainer other than the user, so they are
    #: reported as skipped rather than assessed.
    local: set[str] = field(default_factory=set)
    #: dependencies that come from git, a URL or a local path rather than an
    #: index: name -> "git" | "url" | "path". No registry check can speak to
    #: them, and a scan that dropped them silently would be quietest exactly
    #: where a project keeps its own first-party code.
    not_analysed: dict[str, str] = field(default_factory=dict)
    #: resolved paths already read, so a file reached both by discovery and by
    #: an include is parsed once
    _seen: set[Path] = field(default_factory=set, repr=False)

    def mark_not_analysed(self, name: str, source: str) -> None:
        key = normalise(name) if _VALID_NAME.match(normalise(name)) else name
        if not key or key in self.local:
            return
        self.not_analysed.setdefault(key, source)

    def mark_local(self, name: str) -> None:
        key = normalise(name)
        if key:
            self.local.add(key)
            self.versions.pop(key, None)
            self.direct.discard(key)
            self.origins.pop(key, None)

    def add(
        self,
        name: str,
        version: str | None,
        origin: str,
        direct: bool,
        specifier: str | None = None,
    ) -> None:
        key = normalise(name)
        if key in self.local:
            return
        if not key or key in _IGNORED or not _VALID_NAME.match(key):
            # Lockfiles are just TOML and JSON: nothing in them is validated the
            # way a requirements.txt line is by packaging.Requirement. A crafted
            # uv.lock naming a package "../../simple/evil" would otherwise reach
            # URL construction, so names are checked against PEP 503 here, where
            # every parser passes through.
            return
        if version and "*" in version:
            # `click==8.*` is a range, not a pin. Stored as the version "8.*"
            # it reached OSV as a literal string and matched nothing, which
            # read as "no advisories" for a package that had them.
            version = None
        if version and not self.versions.get(key):
            self.versions[key] = version
        else:
            self.versions.setdefault(key, version)
        if specifier and key not in self.specifiers:
            self.specifiers[key] = specifier
        if direct:
            self.direct.add(key)
        self.origins.setdefault(key, set()).add(origin)

    def __len__(self) -> int:
        return len(self.versions)


def is_dependency_file(path: Path) -> bool:
    """Whether a file is one of the dependency files this tool reads."""
    if path.name in _PARSERS:
        return True
    return path.match(REQUIREMENTS_GLOB) or (
        path.suffix == ".txt"
        and REQUIREMENTS_DIR in (path.parent.name, path.parent.parent.name)
    )


def _files_in(directory: Path) -> list[Path]:
    """The dependency files directly inside one directory, in a fixed order."""
    found: list[Path] = []
    for name in (*LOCKFILES, *MANIFESTS):
        path = directory / name
        if path.is_file():
            found.append(path)
    found.extend(sorted(p for p in directory.glob(REQUIREMENTS_GLOB) if p.is_file()))
    return found


def discover_manifests(root: Path) -> list[Path]:
    """Locate dependency files at the project root.

    Deliberately shallow: recursing finds vendored fixtures and test data, and
    a scan that reports someone else's test fixtures is noise. When the root
    has nothing, `discover_nested` is the bounded fallback.
    """
    found = _files_in(root)
    reqdir = root / REQUIREMENTS_DIR
    if reqdir.is_dir():
        found.extend(sorted(p for p in reqdir.glob("*.txt") if p.is_file()))
        # One level deeper: text-generation-webui keeps requirements/full/*.txt
        # and requirements/portable/*.txt, and pip-tools layouts often do the
        # same per environment. No deeper than that, on purpose.
        found.extend(sorted(p for p in reqdir.glob("*/*.txt") if p.is_file()))
    return found


def discover_nested(root: Path, depth: int = NESTED_DEPTH) -> list[Path]:
    """Dependency files up to ``depth`` directories below a root that has none.

    Used only when the root is empty, so a project with files at the root
    sees no change. Nothing under NESTED_SKIP is entered, and the result is
    every recognised file in the directories that remain, shallowest first,
    so `configs/requirements.txt` is found and `tests/fixtures/requirements.txt`
    is not.
    """
    found: list[Path] = []
    frontier = [root]
    for _ in range(depth):
        next_frontier: list[Path] = []
        for directory in frontier:
            try:
                children = sorted(c for c in directory.iterdir() if c.is_dir())
            except OSError:
                continue
            for child in children:
                if child.name in NESTED_SKIP or child.name.startswith("."):
                    continue
                found.extend(_files_in(child))
                next_frontier.append(child)
        frontier = next_frontier
    return found


def read_manifest(path: Path, max_bytes: int = MAX_MANIFEST_BYTES) -> str | None:
    """Read a dependency file, or return None if it should not be read.

    Only regular files, and only up to the cap. The read itself is bounded
    rather than gated on a prior size check, so a file that grows between the
    two - or a special file that reports no size at all - cannot get past it.
    """
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return None
        with path.open("rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class ParsedRequirement:
    name: str
    #: An exact pin, when the line has one.
    pinned: str | None
    #: The full range as written, when there is one and it is not an exact pin.
    specifier: str | None
    #: A PEP 508 direct reference (`name @ git+ssh://...`): not on any index.
    url: str | None = None

    # The parsers were written against a (name, pinned) pair; keeping that
    # shape means the specifier can be threaded through without touching
    # every call site at once.
    def __getitem__(self, index: int) -> str | None:
        return (self.name, self.pinned)[index]


def source_kind(target: str) -> str | None:
    """"git", "url" or "path" for a requirement that is not an index name."""
    lowered = target.lower()
    if lowered.startswith(_VCS_PREFIXES):
        return "git"
    if lowered.startswith(("http://", "https://", "file:")):
        return "url"
    if target.startswith((".", "/", "~", "\\")) or lowered.endswith((".whl", ".tar.gz", ".zip")):
        return "path"
    return None


_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip")


def _distribution_name(filename: str) -> str | None:
    """``foo`` from ``foo-1.0-py3-none-any.whl`` or ``foo-1.0.tar.gz``.

    A wheel's first dash-separated field is the distribution; an sdist is
    ``name-version`` and the version starts with a digit. Anything else is
    not an archive and gets None.
    """
    lowered = filename.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            stem = filename[: -len(suffix)]
            if suffix == ".whl":
                return stem.split("-", 1)[0] or None
            match = re.match(r"^(.+?)-\d", stem)
            return (match.group(1) if match else stem) or None
    return None


def _name_from_target(target: str, kind: str) -> str:
    """The best name a git URL, a URL or a path offers for the report."""
    if "#egg=" in target:
        return target.split("#egg=", 1)[1].split("&", 1)[0]
    filename = target.split("#", 1)[0].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    distribution = _distribution_name(filename)
    if distribution:
        return distribution
    if kind == "path":
        return target
    # Last path segment, then drop a trailing @revision. The revision split
    # comes second on purpose: `git+ssh://git@github.com/org/repo.git` has an
    # `@` in the host, and splitting on it first left "git" as the name.
    stem = target.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1].split("@", 1)[0]
    if stem.endswith(".git"):
        stem = stem[:-4]
    return stem or target


def _unresolvable_line(line: str) -> tuple[str, str] | None:
    """(name, kind) for a requirements line that no index can answer for."""
    text = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
    for flag in ("-e", "--editable"):
        if text == flag:
            return None
        if text.startswith(flag + " ") or text.startswith(flag + "="):
            text = text[len(flag) + 1:].strip()
            break
    if not text or text.startswith("-"):
        return None
    # Anything the requirement parser accepts is its to handle - a plain
    # name, or `name @ url`, which carries its URL. Only a line it rejects
    # is a bare URL, VCS reference or path. Classifying by suffix first
    # turned `requests @ https://x/requests-2.0.tar.gz` into a "path" named
    # by the whole line.
    try:
        Requirement(text)
    except InvalidRequirement:
        pass
    else:
        return None
    kind = source_kind(text)
    if kind is None:
        return None
    return _name_from_target(text, kind), kind


def _parse_requirement_line(line: str) -> ParsedRequirement | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if not line:
        return None
    # A bare URL, VCS reference or path does not parse as a requirement and
    # is classified by _unresolvable_line instead. A `name @ url` line does
    # parse, and carries its URL, so it must reach the parser: checking the
    # whole line for a URL suffix first dropped `fourth @ https://x/f.whl`.
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return None
    pinned = None
    for spec in req.specifier:
        # `==2024.6.*` is a range, not a pin: it used to be recorded as the
        # pin "2024.6.*", then discarded for containing a wildcard, leaving
        # neither - and the newest release of all was analysed instead of the
        # newest 2024.6. A live advisory disappeared that way.
        if spec.operator in ("==", "===") and "*" not in spec.version:
            pinned = spec.version
            break
    specifier = str(req.specifier) if pinned is None and len(req.specifier) else None
    return ParsedRequirement(req.name, pinned, specifier, req.url)


_INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(?P<target>\S.*?)\s*$")


def _origin(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def parse_requirements_txt(
    path: Path,
    deps: DependencySet,
    text: str,
    root: Path | None = None,
    depth: int = 0,
) -> None:
    """Parse a requirements file, following ``-r`` includes.

    Includes resolve relative to the file that names them, as pip does, and
    are bounded three ways: they must stay inside the project directory, the
    chain may not exceed MAX_INCLUDE_DEPTH, and a file already read is not
    read again. ``-c`` constraints are not followed: they pin what *is*
    installed rather than adding to it.
    """
    root = root or path.parent
    origin = _origin(path, root)
    for raw in text.splitlines():
        include = _INCLUDE.match(raw.strip())
        if include:
            target = (path.parent / include.group("target")).resolve()
            if target in deps._seen:
                continue
            inside = target.is_relative_to(root.resolve())
            if not inside or depth >= MAX_INCLUDE_DEPTH:
                deps.refused.append(target)
                continue
            body = read_manifest(target)
            if body is None:
                deps.refused.append(target)
                continue
            deps._seen.add(target)
            deps.sources.append(target)
            parse_requirements_txt(target, deps, body, root, depth + 1)
            continue
        unresolvable = _unresolvable_line(raw.strip())
        if unresolvable:
            deps.mark_not_analysed(*unresolvable)
            continue
        parsed = _parse_requirement_line(raw)
        if parsed:
            _record(deps, parsed, origin)


def _record(deps: DependencySet, parsed: ParsedRequirement, origin: str) -> None:
    if parsed.url:
        deps.mark_not_analysed(parsed.name, source_kind(parsed.url) or "url")
        return
    deps.add(parsed.name, parsed.pinned, origin, direct=True, specifier=parsed.specifier)


def parse_pyproject(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return

    project = data.get("project") or {}
    own = project.get("name") or ((data.get("tool") or {}).get("poetry") or {}).get("name")
    if isinstance(own, str):
        deps.mark_local(own)
    for item in project.get("dependencies") or []:
        parsed = _parse_requirement_line(str(item))
        if parsed:
            _record(deps, parsed, origin)
    for group in (project.get("optional-dependencies") or {}).values():
        for item in group or []:
            parsed = _parse_requirement_line(str(item))
            if parsed:
                _record(deps, parsed, origin)

    # PEP 735 dependency groups
    for group in (data.get("dependency-groups") or {}).values():
        for item in group or []:
            if isinstance(item, str):
                parsed = _parse_requirement_line(item)
                if parsed:
                    _record(deps, parsed, origin)

    poetry = ((data.get("tool") or {}).get("poetry")) or {}
    sections = [poetry.get(s) or {} for s in ("dependencies", "dev-dependencies")]
    sections += [g.get("dependencies") or {} for g in (poetry.get("group") or {}).values()]
    for section in sections:
        for name, spec in section.items():
            if isinstance(spec, dict):
                for key, kind in (("git", "git"), ("url", "url"), ("path", "path")):
                    if key in spec:
                        deps.mark_not_analysed(str(name), kind)
                        break
                else:
                    deps.add(name, None, origin, direct=True)
                continue
            version = spec if isinstance(spec, str) else None
            pinned = specifier = None
            if isinstance(version, str) and version[:1] == "=":
                exact = version.lstrip("^~= ")
                if "*" in exact:
                    specifier = f"=={exact}"
                else:
                    pinned = exact
            deps.add(name, pinned, origin, direct=True, specifier=specifier)


def parse_setup_cfg(path: Path, deps: DependencySet, text: str) -> None:
    """``[options] install_requires`` and ``[options.extras_require]``.

    setup.cfg is declarative, so this cannot be wrong the way a static read
    of setup.py can: an install_requires computed in Python is invisible to
    a parser, and a partial answer that looks complete is the failure this
    tool exists to avoid. So setup.py is not read at all.
    """
    origin = path.name
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return
    own = parser.get("metadata", "name", fallback=None)
    if own:
        deps.mark_local(own.strip())
    lines = [parser.get("options", "install_requires", fallback="")]
    if parser.has_section("options.extras_require"):
        lines.extend(value for _, value in parser.items("options.extras_require"))
    for block in lines:
        for raw in block.splitlines():
            unresolvable = _unresolvable_line(raw.strip())
            if unresolvable:
                deps.mark_not_analysed(*unresolvable)
                continue
            parsed = _parse_requirement_line(raw)
            if parsed:
                _record(deps, parsed, origin)


def _load_toml(text: str) -> dict | None:
    """Parse TOML, treating anything the parser cannot survive as unparseable.

    tomllib recurses on nested arrays and inline tables, so a crafted lockfile
    a few thousand brackets deep raises RecursionError rather than
    TOMLDecodeError. That must end as "this file is malformed", not as a
    traceback that stops the scan.
    """
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return None


#: uv source kinds that mean "this checkout", not an index.
_UV_LOCAL_SOURCES = ("editable", "directory", "virtual", "workspace", "path")


def parse_uv_lock(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if not name:
            continue
        source = pkg.get("source")
        if isinstance(source, dict) and any(k in source for k in _UV_LOCAL_SOURCES):
            deps.mark_local(str(name))
            continue
        if isinstance(source, dict) and ("git" in source or "url" in source):
            deps.mark_not_analysed(str(name), "git" if "git" in source else "url")
            continue
        deps.add(str(name), pkg.get("version"), origin, direct=False)


def parse_poetry_lock(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if not name:
            continue
        source = pkg.get("source")
        if isinstance(source, dict) and source.get("type") in ("directory", "file"):
            deps.mark_local(str(name))
            continue
        if isinstance(source, dict) and source.get("type") in ("git", "url"):
            deps.mark_not_analysed(str(name), str(source["type"]))
            continue
        deps.add(str(name), pkg.get("version"), origin, direct=False)


_PIPFILE_VERSION = re.compile(r"^==?(?P<v>.+)$")


def parse_pipfile_lock(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        # Older interpreters recurse on nested JSON; see _load_toml.
        return
    if not isinstance(data, dict):
        return
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = specifier = None
            if isinstance(spec, dict):
                if "git" in spec or "file" in spec or "path" in spec:
                    kind = "git" if "git" in spec else ("path" if "path" in spec else "url")
                    deps.mark_not_analysed(str(name), kind)
                    continue
                raw = spec.get("version")
                if isinstance(raw, str):
                    m = _PIPFILE_VERSION.match(raw.strip())
                    version = m.group("v") if m else None
                    if version and "*" in version:
                        specifier, version = f"=={version}", None
            deps.add(str(name), version, origin, direct=False, specifier=specifier)


def parse_pipfile(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for section in ("packages", "dev-packages"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, dict) and ("git" in spec or "path" in spec or "file" in spec):
                kind = "git" if "git" in spec else ("path" if "path" in spec else "url")
                deps.mark_not_analysed(str(name), kind)
                continue
            specifier = None
            if isinstance(spec, str) and spec.strip() not in ("", "*"):
                specifier = spec.strip()
            deps.add(str(name), None, origin, direct=True, specifier=specifier)


_PARSERS = {
    "pyproject.toml": parse_pyproject,
    "setup.cfg": parse_setup_cfg,
    "uv.lock": parse_uv_lock,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Pipfile": parse_pipfile,
}


def collect_dependencies(
    paths: list[Path], max_bytes: int = MAX_MANIFEST_BYTES, root: Path | None = None
) -> DependencySet:
    """Parse every discovered file. ``root`` is the project directory, which
    bounds where requirements includes may reach; it defaults to the first
    file's directory."""
    deps = DependencySet()
    if root is None and paths:
        root = paths[0].parent
    for path in paths:
        is_requirements = path.match(REQUIREMENTS_GLOB) or (
            path.suffix == ".txt"
            and REQUIREMENTS_DIR in (path.parent.name, path.parent.parent.name)
        )
        parser = _PARSERS.get(path.name)
        if parser is None and is_requirements:
            parser = parse_requirements_txt
        if parser is None:
            continue
        resolved = path.resolve()
        if resolved in deps._seen:
            continue
        text = read_manifest(path, max_bytes)
        if text is None:
            deps.refused.append(path)
            continue
        deps._seen.add(resolved)
        deps.sources.append(path)
        if parser is parse_requirements_txt:
            parse_requirements_txt(path, deps, text, root)
        else:
            parser(path, deps, text)
    return deps
