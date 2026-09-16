"""The guardrail: one decision per package, at the moment it is being added.

A scan finds problems after they are in the lockfile. A coding agent adds a
dependency in the time it takes to complete an import statement, and never
reads the PyPI page, so the useful moment is before ``pip install`` runs.
This module turns a finding into a decision an installer, a hook or an
agent can act on: *block*, *warn*, *ok*, or *unchecked*.

Agents fail in a way people rarely do: they invent names. Three facts cover
that, and they are facts rather than inferences, so they can block:

* **not on PyPI** - an install would fail, or fetch whatever someone
  registered under the invented name since;
* **registered recently** - a package that appeared days ago under exactly
  the name that was just guessed is the documented slopsquatting pattern;
* **one edit from a popular name** - the shape of a typo, or of a squat.

These are about provenance, not exposure. They live here rather than in the
exposure map or the risk rules, and they never touch a verdict.

The rest follows the verdict the scanner already reached, and blocks exactly
what a scan of the same package would fail on: *fix today* wherever it is
found, and a *replace* or *upgrade* at a reviewed trust boundary. A finding
that would not stop a build does not stop an install either - *mitigate*, the
same facts away from a boundary, and a boundary package that has gone quiet
all warn, and a package with nothing to do about it says nothing at all. And
when the upstream services could not answer, the package is *unchecked* and
allowed: a guardrail that fails closed on somebody else's outage is the first
thing a team removes.
"""

from __future__ import annotations

import datetime as dt
import re
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from .models import Boundary, Finding, Verdict
from .parsers.discovery import _PARSERS as _MANIFEST_PARSERS
from .parsers.discovery import (
    LOCKFILES,
    MANIFESTS,
    REQUIREMENTS_DIR,
    REQUIREMENTS_GLOB,
    DependencySet,
    collect_dependencies,
    parse_requirements_txt,
)
from .sources.pypi import normalise

POPULAR_FILE = Path(__file__).parent / "data" / "popular.txt"

#: A package first uploaded within this many days is blocked by default.
NEW_DAYS = 30

BLOCK, WARN, OK, UNCHECKED = "block", "warn", "ok", "unchecked"
LEVEL_ORDER = (BLOCK, WARN, OK, UNCHECKED)


@dataclass(frozen=True)
class Provenance:
    found: bool | None = None
    first_release: dt.datetime | None = None
    days_since_first_release: int | None = None
    #: A far more common package one edit away, when this one is not itself common.
    near_miss: str | None = None


@dataclass
class Decision:
    level: str
    reasons: list[str] = field(default_factory=list)
    provenance: Provenance = Provenance()

    @property
    def blocked(self) -> bool:
        return self.level == BLOCK


# --- popular names and near misses -----------------------------------------

@lru_cache(maxsize=1)
def load_popular(path: Path | None = None) -> tuple[str, ...]:
    """Most-downloaded package names, most popular first."""
    target = path or POPULAR_FILE
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    return tuple(normalise(line.strip()) for line in lines
                 if line.strip() and not line.startswith("#"))


def one_edit_apart(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance of exactly one: an insertion, a deletion,
    a substitution, or two adjacent characters swapped."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    short, long = (a, b) if la < lb else (b, a)
    i = 0
    while i < len(short) and short[i] == long[i]:
        i += 1
    return short[i:] == long[i + 1:]


def near_miss(name: str, popular: Sequence[str]) -> str | None:
    """The popular package this name is one edit away from, if this name is
    not itself popular.

    Two characters or fewer is skipped outright - at that length almost any
    string is one edit from something. Above that, the skip narrows instead
    of disappearing: for a 3-4 character name, only a same-length edit
    (a substitution or an adjacent swap) counts. That is the actual shape a
    typo or a squat takes - ``tomI`` for ``toml``, ``gprc`` for ``grpc`` -
    real, popular, four-character packages that a full skip at this length
    left with zero coverage. An insertion or deletion is excluded at this
    length instead: ``sixx`` is one deletion from the real package ``six``
    with no squatting behind it at all, purely because short strings are
    dense enough that a random one nearly always lands next to *something*
    in a large popular list once insertions and deletions are allowed. Above
    four characters this restriction does not apply, since coincidental
    collisions get rare fast as strings get longer.
    """
    key = normalise(name)
    if len(key) <= 2 or key in popular:
        return None
    for candidate in popular:
        if len(key) <= 4 and len(candidate) != len(key):
            continue
        if one_edit_apart(key, candidate):
            return candidate
    return None


# --- what an install command asks for -------------------------------------

#: Options that consume the next token, so it is not read as a package.
_TAKES_VALUE = {
    "-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url",
    "-t", "--target", "--python", "-p", "--prefix", "--root", "-f", "--find-links",
    "--group", "-G", "--optional", "--index", "--default-index", "--cache-dir",
    "--config-settings", "-C", "--build-constraint", "--platform", "--only-binary",
    "--no-binary", "--implementation", "--abi", "--progress-bar", "--log", "--proxy",
    "--retries", "--timeout", "--exists-action", "--trusted-host", "--cert",
    "--client-cert", "--report", "--src", "-e", "--editable", "--branch", "--tag", "--rev",
}

#: (verb tokens) that mean "install these names". Matched as a contiguous
#: run of tokens anywhere in a segment, so `python -m pip install` works.
_INSTALLERS: tuple[tuple[str, ...], ...] = (
    ("pip", "install"), ("pip3", "install"), ("uv", "pip", "install"), ("uv", "add"),
    ("poetry", "add"), ("pipenv", "install"), ("pdm", "add"), ("pipx", "install"),
    ("pipx", "inject"),
)
_SEPARATORS = {"&&", "||", ";", "|", "&"}
_PIP_LIKE = re.compile(r"^(python[0-9.]*|py)$")


def _segments(command: str) -> list[list[str]]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return []
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [seg for seg in segments if seg]


_LOCAL_ONLY_PREFIXES = (".", "/", "~", "file:")
_VCS_SCHEMES = ("git+", "hg+", "bzr+", "svn+")
_REMOTE_PREFIXES = ("http://", "https://", "ssh://", "git://") + _VCS_SCHEMES


def is_remote_install_target(target: str) -> bool:
    """Whether ``target`` is a URL or VCS reference pip would fetch over the
    network, as opposed to a local path, wheel, or bare filename.

    ``_looks_local`` treats both kinds alike as "not a checkable PyPI name",
    which is right for skipping the registry lookup. A caller deciding what
    to block outright needs to tell them apart instead: a local wheel is
    unresolvable for the same reason but isn't a network fetch. Covers every
    VCS scheme pip supports, including the ``bzr+lp:name`` Launchpad
    shorthand (still prefixed with ``bzr+``).
    """
    return target.lower().startswith(_REMOTE_PREFIXES)


def _looks_local(arg: str) -> bool:
    lowered = arg.lower()
    return (
        arg.startswith(_LOCAL_ONLY_PREFIXES)
        or is_remote_install_target(arg)
        or lowered.endswith((".whl", ".tar.gz", ".zip", ".txt", ".toml", ".egg"))
        or "/" in arg
        or "\\" in arg
    )


def _install_positionals(command: str) -> list[str]:
    """Positional arguments to a recognised installer invocation, in order.

    Handles the pip, uv, poetry, pipenv, pdm and pipx spellings, ``python -m
    pip``, chained commands, and quoted specifiers. Option tokens and their
    values are dropped, and ``pipx inject app pkg`` drops the app - but
    everything else passes through unfiltered, including local paths, VCS
    references and URLs, so callers can each classify what they see rather
    than losing it here.
    """
    tokens: list[str] = []
    for seg in _segments(command):
        # `python -m pip install` -> drop the interpreter prefix.
        if len(seg) >= 3 and _PIP_LIKE.match(seg[0]) and seg[1] == "-m":
            seg = seg[2:]
        start = None
        for verb in _INSTALLERS:
            for i in range(len(seg) - len(verb) + 1):
                if tuple(seg[i : i + len(verb)]) == verb:
                    start = i + len(verb)
                    break
            if start is not None:
                if verb == ("pipx", "inject"):
                    # The first positional is the app, not a package to check.
                    skipped_app = False
                    rest = []
                    for tok in seg[start:]:
                        if not tok.startswith("-") and not skipped_app:
                            skipped_app = True
                            continue
                        rest.append(tok)
                    seg = rest
                    start = 0
                break
        if start is None:
            continue
        skip_next = False
        for tok in seg[start:]:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                if tok in _TAKES_VALUE:
                    skip_next = True
                continue
            tokens.append(tok)
    return tokens


def parse_install_command(command: str) -> list[str]:
    """Requirement strings an install command would add, in order.

    Paths, URLs and local files are skipped, since no registry check can say
    anything about them - see ``unresolvable_install_targets`` for those.
    """
    found: list[str] = []
    for tok in _install_positionals(command):
        if _looks_local(tok):
            continue
        try:
            req = Requirement(tok)
        except InvalidRequirement:
            continue
        found.append(tok)
        del req
    return found


def unresolvable_install_targets(command: str) -> list[str]:
    """Install arguments this guardrail has no way to check: paths, VCS
    references, and direct URLs.

    ``parse_install_command`` excludes these because there is no PyPI name to
    check them against, which is correct - a registry lookup cannot say
    anything about a wheel fetched straight from a URL. But it means
    ``pip install https://evil.example/pkg.whl`` currently produces the same
    silence from the guardrail as an empty command, even though installing
    straight from an arbitrary URL is the highest-risk form of install there
    is. This surfaces exactly the arguments that were dropped, so a caller
    can tell "nothing here to check" apart from "the one thing here is the
    kind this guardrail cannot check at all" and warn accordingly, rather
    than silently treating it as clean.
    """
    return [tok for tok in _install_positionals(command) if _looks_local(tok)]


# --- what an edit to a dependency file just added ---------------------------

def is_manifest(path: Path) -> bool:
    """A file a person or agent writes dependencies into by hand.

    Lockfiles are deliberately excluded: a resolver rewriting uv.lock
    produces a diff of every transitive package, and checking that on every
    sync would be a full scan, not a guardrail.
    """
    if path.name in MANIFESTS or path.match(REQUIREMENTS_GLOB):
        return True
    return path.suffix == ".txt" and REQUIREMENTS_DIR in (
        path.parent.name, path.parent.parent.name if path.parent.parent != path.parent else "",
    )


def _requirement_strings(deps: DependencySet, names: set[str]) -> list[str]:
    out = []
    for name in sorted(names):
        pinned = deps.versions.get(name)
        if pinned:
            out.append(f"{name}=={pinned}")
        elif deps.specifiers.get(name):
            out.append(f"{name}{deps.specifiers[name]}")
        else:
            out.append(name)
    return out


def _previous_text(path: Path, root: Path) -> str | None:
    """The file as git last committed it, or None outside a repository."""
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{rel}"],
            cwd=root, capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _parse_text(path: Path, text: str, root: Path) -> DependencySet:
    deps = DependencySet()
    parser = _MANIFEST_PARSERS.get(path.name)
    if parser is not None:
        parser(path, deps, text)
    else:
        parse_requirements_txt(path, deps, text, root)
    return deps


def added_requirements(path: Path, root: Path) -> list[str]:
    """Requirement strings for the names an edit to ``path`` introduced.

    A name counts as added when it is in the file now and in neither the
    project's lockfiles nor the version of the file git last committed.
    Without a repository or a lockfile everything in the file is new, and
    is checked; that is rare, and the alternative is checking nothing.
    """
    if not is_manifest(path) or not path.is_file():
        return []
    now = collect_dependencies([path], root=root)
    if not now.versions:
        return []
    known: set[str] = set()
    for name in LOCKFILES:
        lock = root / name
        if lock.is_file():
            known |= set(collect_dependencies([lock], root=root).versions)
    previous = _previous_text(path, root)
    if previous is not None:
        known |= set(_parse_text(path, previous, root).versions)
    return _requirement_strings(now, set(now.versions) - known)


def parse_requirement(text: str) -> tuple[str, str | None, str | None]:
    """(name, pinned version, specifier) from one requirement string."""
    req = Requirement(text)
    pinned = None
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            pinned = spec.version
            break
    specifier = str(req.specifier) if pinned is None and len(req.specifier) else None
    return req.name, pinned, specifier


# --- the decision -----------------------------------------------------------

def decide(
    finding: Finding,
    *,
    now: dt.datetime,
    popular: Sequence[str] = (),
    new_days: int = NEW_DAYS,
    degraded: bool = False,
) -> Decision:
    rem = finding.remediation
    name = finding.package.name
    miss = near_miss(name, popular)

    if finding.error == "not found on PyPI":
        reasons = ["not on PyPI: an install would fail, or fetch whatever someone has "
                   "registered under this name since"]
        if miss:
            reasons.append(f"one edit from {miss}; did you mean that?")
        return Decision(BLOCK, reasons, Provenance(found=False, near_miss=miss))

    if finding.error or (degraded and rem.last_release is None):
        # The lookup itself failed. That is not evidence about the package,
        # and blocking on it would make an outage elsewhere stop all work.
        return Decision(
            UNCHECKED,
            [f"could not be checked ({finding.error or 'upstream trouble'}); "
             "allowed rather than blocked - rerun when the services answer"],
            Provenance(found=None, near_miss=miss),
        )

    age = (now - rem.first_release).days if rem.first_release else None
    provenance = Provenance(True, rem.first_release, age, miss)
    reasons: list[str] = []
    level = OK

    if age is not None and age <= new_days:
        level = BLOCK
        reasons.append(
            f"first published {age} day{'s' if age != 1 else ''} ago: too new to have "
            f"a track record, and a name registered this recently is worth a human look"
        )
    if miss:
        reasons.append(
            f"one edit from {miss}, a far more common package; make sure this is the "
            f"one you meant"
        )
        if level == OK:
            level = WARN

    verdict = finding.verdict
    claims = [r.claim for r in finding.reasons]
    if finding.blocks:
        # Exactly what fails a scan: exploited wherever it is found, or a
        # replacement or upgrade at a reviewed trust boundary. The hook and CI
        # never disagree about what is worth refusing.
        level = BLOCK
        reasons.append("; ".join(claims[:3]) or "no one left to fix it")
    elif verdict in (Verdict.REPLACE, Verdict.UPGRADE, Verdict.MITIGATE):
        # The same facts away from a reviewed boundary, or an advisory nobody
        # can fix. Worth saying before the package is added; not worth refusing.
        if level == OK:
            level = WARN
        reasons.append("; ".join(claims[:2]) or verdict.value)
    elif verdict is Verdict.QUIET and finding.exposure.boundary is Boundary.AT:
        # Nothing is wrong with it, but it handles attacker-influenced data and
        # nobody has shipped in years: the one thing worth a line of context
        # before an agent adopts it.
        if level == OK:
            level = WARN
        detail = "; ".join(claims[:2]) or "has gone quiet"
        reasons.append(f"at a trust boundary ({finding.exposure.label}): {detail}")
    elif not reasons:
        # Nothing to do about this one. A guardrail that comments on healthy
        # packages is one an agent learns to skim: `httpx` and `fastapi` are
        # exactly what it should be reaching for.
        if verdict is Verdict.QUIET and claims:
            reasons.append(f"not at a known boundary; {claims[0]}")
        elif verdict is Verdict.UNCHECKED:
            reasons.append("no exposure signal and no maintenance signal")
        else:
            reasons.append(
                "reviewed as not at a trust boundary" if finding.exposure.note
                else "no concerns found"
            )
    return Decision(level, reasons, provenance)
