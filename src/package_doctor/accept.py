"""Accepted risks: the file that keeps a known finding from failing every build.

The first false positive - or the first true positive with a ticket already
filed - is where a scanner gets removed from CI. The alternative is a way to
say "we know, here is why, and here is when we will look again". Three rules
make that safe to offer:

* **Every acceptance names a reason.** Six months on, an entry with no reason
  cannot be told from a mistake.
* **Every acceptance expires.** A permanent suppression is how a known
  exposure survives every review. When one runs out, the finding fails the
  build again and the report says the acceptance expired, not that something
  new appeared.
* **Accepted findings stay in the report.** They move to their own section
  and stop affecting the exit code. They never disappear.

A malformed file is a usage error, not a warning: an entry that silently
failed to apply would fail a build for no visible reason, and one that
silently applied more widely than written would hide risk.
"""

from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import Acceptance, Finding, Verdict
from .sources.pypi import normalise

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

#: The file read from the project root. Kept next to the lockfile so that
#: the acceptances are reviewed with the dependencies they are about.
CONFIG_NAME = "package-doctor.toml"

#: Largest configuration file that will be read. There is no honest reason for
#: one to approach this.
MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(ValueError):
    """The acceptance file could not be read as written. Fails the run."""


@dataclass
class Acceptances:
    entries: list[Acceptance] = field(default_factory=list)
    #: Where they came from, for the report. None when no file was found.
    path: Path | None = None


def load_acceptances(root: Path, explicit: Path | None = None) -> Acceptances:
    """Read acceptances for a project.

    ``package-doctor.toml`` at the project root wins. Without one, a
    ``[tool.package-doctor]`` table in ``pyproject.toml`` is read, so a
    project that keeps every tool's settings in one file need not add
    another. An explicit path is used as given and must exist.
    """
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"acceptance file not found: {explicit}")
        return Acceptances(_parse(_read(explicit), explicit, top_level=True), explicit)

    candidate = root / CONFIG_NAME
    if candidate.is_file():
        return Acceptances(_parse(_read(candidate), candidate, top_level=True), candidate)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _read(pyproject)
        table = (data.get("tool") or {}).get("package-doctor")
        if isinstance(table, dict):
            return Acceptances(_parse(table, pyproject, top_level=False), pyproject)
    return Acceptances()


def _read(path: Path) -> dict:
    # Bounded read, not read-then-check: this file can come from a project
    # package-doctor does not control (a checked-in package-doctor.toml, or a
    # [tool.package-doctor] table in a pyproject.toml pulled in by a CI job
    # scanning an external PR). Reading the whole thing before measuring it
    # defeats the point of the cap - an oversized file is fully buffered in
    # memory by the time it is rejected. One byte past the limit is enough to
    # know it is too large without ever reading the rest of it.
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_CONFIG_BYTES // 1024} KB; not read")
    try:
        data = tomllib.loads(raw.decode("utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    return data


def _parse(data: dict, path: Path, *, top_level: bool) -> list[Acceptance]:
    where = str(path) if top_level else f"{path} [tool.package-doctor]"
    raw = data.get("accept")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError(f"{where}: 'accept' must be an array of tables ([[accept]])")

    entries: list[Acceptance] = []
    for i, item in enumerate(raw, start=1):
        label = f"{where}: accept entry {i}"
        if not isinstance(item, dict):
            raise ConfigError(f"{label} must be a table")
        name = item.get("package")
        if not isinstance(name, str) or not normalise(name):
            raise ConfigError(f"{label} needs a 'package' name")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(
                f"{label} ({name}) needs a 'reason' - a suppression with no reason "
                f"cannot be told from a mistake later"
            )
        until = item.get("until")
        if isinstance(until, dt.datetime):
            until = until.date()
        if not isinstance(until, dt.date):
            raise ConfigError(
                f"{label} ({name}) needs an 'until' date (YYYY-MM-DD) - acceptances "
                f"expire so that a known risk is looked at again"
            )
        version = item.get("version")
        if version is not None and not isinstance(version, str):
            raise ConfigError(f"{label} ({name}): 'version' must be a string")
        unknown = set(item) - {"package", "reason", "until", "version"}
        if unknown:
            raise ConfigError(
                f"{label} ({name}) has unknown key{'s' if len(unknown) > 1 else ''}: "
                f"{', '.join(sorted(unknown))}"
            )
        entries.append(
            Acceptance(
                package=normalise(name),
                reason=reason.strip(),
                until=until,
                version=version.strip() if version else None,
                source=path.name,
            )
        )
    return entries


def apply_acceptances(
    findings: list[Finding], acceptances: Acceptances, now: dt.datetime
) -> list[str]:
    """Attach acceptances to the findings they name.

    Returns notes for the user about entries that did not do anything: a
    package that was not scanned, a version that no longer matches, or a
    finding that needed no accepting. A stale entry is worth a line, because
    the file is supposed to be a list of live decisions.
    """
    today = now.date()
    by_name = {f.package.name: f for f in findings}
    notes: list[str] = []
    for entry in acceptances.entries:
        finding = by_name.get(entry.package)
        if finding is None:
            notes.append(
                f"acceptance for {entry.package} matched no scanned package "
                f"({entry.source})"
            )
            continue
        pinned = finding.package.version
        if entry.version is not None and pinned != entry.version:
            notes.append(
                f"acceptance for {entry.package} is for version {entry.version}, "
                f"but {pinned or 'no version'} is "
                f"{'assumed' if finding.package.version_assumed else 'pinned'} - not applied"
            )
            continue
        if finding.verdict is Verdict.OK:
            notes.append(f"acceptance for {entry.package} is not needed: nothing to accept")
            continue
        if finding.accepted is not None:
            notes.append(f"acceptance for {entry.package} is listed twice; the first applies")
            continue
        finding.accepted = entry
        finding.acceptance_expired = entry.until < today
    return notes
