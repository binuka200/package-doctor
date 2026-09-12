"""Find and parse dependency declarations.

Manifests tell us what a project asked for (its *direct* dependencies).
Lockfiles tell us what actually gets installed, transitives included - which is
where the neglected packages usually live. We read both and remember which
source each name came from, because "I never chose this" changes how a user
reacts to a finding.
"""

from __future__ import annotations

import re
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
    return found


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


def parse_requirements_txt(path: Path, deps: DependencySet) -> None:
    origin = path.name
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _parse_requirement_line(raw)
        if parsed:
            deps.add(parsed[0], parsed[1], origin, direct=True)


def parse_pyproject(path: Path, deps: DependencySet) -> None:
    origin = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
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


def parse_uv_lock(path: Path, deps: DependencySet) -> None:
    origin = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name:
            deps.add(str(name), pkg.get("version"), origin, direct=False)


def parse_poetry_lock(path: Path, deps: DependencySet) -> None:
    origin = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name:
            deps.add(str(name), pkg.get("version"), origin, direct=False)


_PIPFILE_VERSION = re.compile(r"^==?(?P<v>.+)$")


def parse_pipfile_lock(path: Path, deps: DependencySet) -> None:
    import json

    origin = path.name
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
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


def parse_pipfile(path: Path, deps: DependencySet) -> None:
    origin = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
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


def collect_dependencies(paths: list[Path]) -> DependencySet:
    deps = DependencySet()
    for path in paths:
        parser = _PARSERS.get(path.name)
        if parser is None and path.match(REQUIREMENTS_GLOB):
            parser = parse_requirements_txt
        if parser is None:
            continue
        parser(path, deps)
        deps.sources.append(path)
    return deps
