"""Find and parse dependency declarations.

Manifests tell us what a project asked for (its *direct* dependencies).
Lockfiles tell us what actually gets installed, transitives included - which is
where the neglected packages usually live. We read both and remember which
source each name came from, because "I never chose this" changes how a user
reacts to a finding.
"""

from __future__ import annotations

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

MANIFESTS = ("pyproject.toml", "Pipfile")
LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock")
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

#: Packages that ship with CPython or the packaging toolchain; scanning them
#: tells the user nothing they can act on.
_IGNORED = {"python", "pip", "setuptools", "wheel", "setuptools-scm"}


@dataclass
class DependencySet:
    #: normalised name -> pinned version (or None when only a range is known)
    versions: dict[str, str | None] = field(default_factory=dict)
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
    #: resolved paths already read, so a file reached both by discovery and by
    #: an include is parsed once
    _seen: set[Path] = field(default_factory=set, repr=False)

    def add(self, name: str, version: str | None, origin: str, direct: bool) -> None:
        key = normalise(name)
        if not key or key in _IGNORED or not _VALID_NAME.match(key):
            # Lockfiles are just TOML and JSON: nothing in them is validated the
            # way a requirements.txt line is by packaging.Requirement. A crafted
            # uv.lock naming a package "../../simple/evil" would otherwise reach
            # URL construction, so names are checked against PEP 503 here, where
            # every parser passes through.
            return
        if version and not self.versions.get(key):
            self.versions[key] = version
        else:
            self.versions.setdefault(key, version)
        if direct:
            self.direct.add(key)
        self.origins.setdefault(key, set()).add(origin)

    def __len__(self) -> int:
        return len(self.versions)


def discover_manifests(root: Path) -> list[Path]:
    """Locate dependency files at the project root.

    Deliberately shallow: recursing finds vendored fixtures and test data, and
    a scan that reports someone else's test fixtures is noise.
    """
    found: list[Path] = []
    for name in (*LOCKFILES, *MANIFESTS):
        path = root / name
        if path.is_file():
            found.append(path)
    found.extend(sorted(p for p in root.glob(REQUIREMENTS_GLOB) if p.is_file()))
    reqdir = root / REQUIREMENTS_DIR
    if reqdir.is_dir():
        found.extend(sorted(p for p in reqdir.glob("*.txt") if p.is_file()))
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


def _parse_requirement_line(line: str) -> tuple[str, str | None] | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if not line or line.startswith(("http://", "https://", "git+", ".", "/")):
        return None
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return None
    pinned = None
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            pinned = spec.version
            break
    return req.name, pinned


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
        parsed = _parse_requirement_line(raw)
        if parsed:
            deps.add(parsed[0], parsed[1], origin, direct=True)


def parse_pyproject(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return

    project = data.get("project") or {}
    for item in project.get("dependencies") or []:
        parsed = _parse_requirement_line(str(item))
        if parsed:
            deps.add(parsed[0], parsed[1], origin, direct=True)
    for group in (project.get("optional-dependencies") or {}).values():
        for item in group or []:
            parsed = _parse_requirement_line(str(item))
            if parsed:
                deps.add(parsed[0], parsed[1], origin, direct=True)

    # PEP 735 dependency groups
    for group in (data.get("dependency-groups") or {}).values():
        for item in group or []:
            if isinstance(item, str):
                parsed = _parse_requirement_line(item)
                if parsed:
                    deps.add(parsed[0], parsed[1], origin, direct=True)

    poetry = ((data.get("tool") or {}).get("poetry")) or {}
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            version = spec if isinstance(spec, str) else None
            pinned = (
                version.lstrip("^~= ")
                if isinstance(version, str) and version[:1] == "="
                else None
            )
            deps.add(name, pinned, origin, direct=True)
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            deps.add(name, None, origin, direct=True)


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


def parse_uv_lock(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name:
            deps.add(str(name), pkg.get("version"), origin, direct=False)


def parse_poetry_lock(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name:
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
            version = None
            if isinstance(spec, dict):
                raw = spec.get("version")
                if isinstance(raw, str):
                    m = _PIPFILE_VERSION.match(raw.strip())
                    version = m.group("v") if m else None
            deps.add(str(name), version, origin, direct=False)


def parse_pipfile(path: Path, deps: DependencySet, text: str) -> None:
    origin = path.name
    data = _load_toml(text)
    if data is None:
        return
    for section in ("packages", "dev-packages"):
        for name in (data.get(section) or {}):
            deps.add(str(name), None, origin, direct=True)


_PARSERS = {
    "pyproject.toml": parse_pyproject,
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
            path.parent.name == REQUIREMENTS_DIR and path.suffix == ".txt"
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
