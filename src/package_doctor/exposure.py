"""Axis 1: deciding whether a package sits at a trust boundary.

Two tiers, and the distinction is reported to the user rather than hidden:

* **curated** - a human put it in ``data/exposure.toml`` with a reason.
* **inferred** - guessed from PyPI classifiers and keywords for the long tail.

Anything else gets no opinion at all. An unknown exposure is reported as
unknown; it is never quietly treated as "safe" or as "risky".
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import Confidence, Exposure
from .sources.pypi import normalise

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

DATA_FILE = Path(__file__).parent / "data" / "exposure.toml"

#: Trove classifiers that imply a trust boundary, mapped to a category label.
_CLASSIFIER_HINTS: tuple[tuple[str, str], ...] = (
    # Only classifiers that say something about *handling untrusted input*.
    #
    # Measured against 3,000 packages, the broader set this replaced carried no
    # signal at all: packages it marked exposed had advisories at 11.3%, against
    # 12.1% for packages reviewed and marked NOT exposed. It was guessing.
    #
    # A hand audit of what it guessed showed why. "Topic :: Security" caught
    # bandit, semgrep and pip-audit - security *tools*, not trust boundaries.
    # "Topic :: System :: Archiving" caught setuptools and wheel. "Topic ::
    # Multimedia :: Graphics" caught seaborn and pydeck, which plot trusted
    # dataframes. "Framework :: Django" caught pytest-django and factory-boy.
    # Roughly three in five were wrong.
    ("Topic :: Security :: Cryptography", "crypto"),
    ("Topic :: Internet :: WWW/HTTP :: Session", "auth/session"),
    ("Topic :: Text Processing :: Markup :: HTML", "html/xml parsing"),
    ("Topic :: Text Processing :: Markup :: XML", "html/xml parsing"),
    ("Topic :: Internet :: WWW/HTTP :: WSGI", "http/network"),
)

#: Keyword fragments used only as a weak fallback, and only when a classifier
#: said nothing. Kept short on purpose: broad keyword matching is how these
#: tools start flagging things like `colorama` as a security concern.
_KEYWORD_HINTS: tuple[tuple[str, str], ...] = (
    # Narrow and specific. A keyword only counts when the word itself names a
    # protocol or primitive that exists to process untrusted input.
    ("oauth", "auth/session"),
    ("saml", "auth/session"),
    ("openid", "auth/session"),
    ("deserializ", "deserialization"),
    ("sanitiz", "html/xml parsing"),
)

def entries(block: Any) -> list[tuple[str, str | None]]:
    """The (name, why) pairs of one list in the map.

    An entry is either a bare name or a table ``{ name = "...", why = "..." }``.
    The second form is the one that makes the map arguable: a reader can see
    what convinced the curator without redoing the research, and a reviewer
    can disagree with a sentence rather than with a name. Both forms load,
    so the file can grow evidence entry by entry.
    """
    out: list[tuple[str, str | None]] = []
    for item in block or []:
        if isinstance(item, dict):
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"exposure map entry without a name: {item!r}")
            why = item.get("why")
            reason = why.strip() if isinstance(why, str) and why.strip() else None
            out.append((name.strip(), reason))
        else:
            out.append((str(item), None))
    return out


#: What a flaw at each kind of boundary tends to cost, worst first.
#:
#: This is a vocabulary, not a score. Each category names one of these, the
#: report uses the order to break ties between findings with the same
#: evidence - a stale pickle loader above a stale JSON parser - and
#: `explain` shows the word. Nothing sums it, weights it, or turns it into
#: a number, and it never changes a verdict.
CONSEQUENCE_ORDER: tuple[str, ...] = (
    "code execution",
    "memory corruption",
    "file write",
    "account takeover",
    "data access",
    "script injection",
    "request forgery",
    "prompt injection",
    "denial of service",
)


def consequence_rank(value: str | None) -> int:
    """Position in CONSEQUENCE_ORDER; unknown or absent sorts last."""
    try:
        return CONSEQUENCE_ORDER.index(value) if value else len(CONSEQUENCE_ORDER)
    except ValueError:
        return len(CONSEQUENCE_ORDER)


class ExposureMap:
    def __init__(self, data: dict[str, Any]):
        self._by_package: dict[str, list[str]] = {}
        self._labels: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}
        #: label -> consequence word, validated against the vocabulary.
        self._consequences: dict[str, str] = {}
        #: normalised name -> the recorded reason for its entry, when there is one.
        self._why: dict[str, str] = {}
        for key, block in (data.get("category") or {}).items():
            label = block.get("label", key)
            self._labels[key] = label
            self._descriptions[key] = block.get("description", "")
            consequence = block.get("consequence")
            if consequence is not None:
                if consequence not in CONSEQUENCE_ORDER:
                    raise ValueError(
                        f"category.{key}: consequence {consequence!r} is not one of "
                        f"{', '.join(CONSEQUENCE_ORDER)}"
                    )
                self._consequences[label] = consequence
            for name, why in entries(block.get("packages")):
                self._by_package.setdefault(normalise(name), []).append(label)
                if why:
                    self._why[normalise(name)] = why
        stable_block = data.get("stable") or {}
        self._stable = set()
        for name, why in entries(stable_block.get("packages")):
            self._stable.add(normalise(name))
            if why:
                self._why[normalise(name)] = why
        # Reviewed and deliberately not exposed. Distinct from "never looked at":
        # an entry here suppresses metadata inference, so a package cannot be
        # flagged just because its name or classifiers sound security-adjacent.
        self._reviewed_safe = set()
        for name, why in entries((data.get("reviewed") or {}).get("not_exposed")):
            self._reviewed_safe.add(normalise(name))
            if why:
                self._why[normalise(name)] = why
        # At a trust boundary AND deliberately finished. Keeps the exposure
        # category - these packages genuinely handle untrusted input - while
        # exempting them from age-based reasoning.
        self._mature = set()
        for name, why in entries(stable_block.get("mature")):
            self._mature.add(normalise(name))
            if why:
                self._why[normalise(name)] = why

    @property
    def size(self) -> int:
        """Packages with a curated exposure category."""
        return len(self._by_package)

    @property
    def reviewed_size(self) -> int:
        """Every package a human has made a call on, either way."""
        return len(self._by_package) + len(self._stable) + len(self._reviewed_safe)

    def is_reviewed(self, name: str) -> bool:
        key = normalise(name)
        return key in self._by_package or key in self._stable or key in self._reviewed_safe

    def why(self, name: str) -> str | None:
        """The recorded reason behind a package's entry, if the curator left one."""
        return self._why.get(normalise(name))

    @property
    def explained(self) -> int:
        """Entries that carry a reason. The number to grow."""
        return len(self._why)

    def is_known_stable(self, name: str) -> bool:
        """True for packages where release age carries no information.

        Covers finished utilities away from any trust boundary, and libraries
        that are at one but are complete by design. Suppresses weak signals
        only: an archived repository or an unfixed advisory still escalates.
        """
        key = normalise(name)
        return key in self._stable or key in self._mature

    def describe(self, label: str) -> str:
        for key, value in self._labels.items():
            if value == label:
                return self._descriptions.get(key, "")
        return ""

    def consequence(self, labels: Iterable[str]) -> str | None:
        """The worst consequence among some category labels, or None."""
        found = [self._consequences[lbl] for lbl in labels if lbl in self._consequences]
        return min(found, key=consequence_rank) if found else None

    def lookup(self, name: str, pypi_info: dict[str, Any] | None = None) -> Exposure:
        key = normalise(name)
        why = self._why.get(key)
        curated = self._by_package.get(key)
        if curated:
            labels = sorted(set(curated))
            return Exposure(
                categories=labels, confidence=Confidence.CURATED, why=why,
                consequence=self.consequence(labels),
            )

        if key in self._stable:
            return Exposure(
                categories=[],
                confidence=Confidence.CURATED,
                note="reviewed: stable utility, not at a trust boundary",
                why=why,
            )

        if key in self._reviewed_safe:
            return Exposure(
                categories=[],
                confidence=Confidence.CURATED,
                note="reviewed: not at a trust boundary",
                why=why,
            )

        if pypi_info:
            inferred = self._infer(pypi_info)
            if inferred:
                return Exposure(
                    categories=inferred,
                    confidence=Confidence.INFERRED,
                    note="inferred from PyPI metadata, not human-reviewed",
                    consequence=self.consequence(inferred),
                )
            return Exposure(categories=[], confidence=Confidence.INFERRED)

        return Exposure(categories=[], confidence=Confidence.NONE)

    def _infer(self, pypi_info: dict[str, Any]) -> list[str]:
        classifiers = pypi_info.get("classifiers") or []
        hits: list[str] = []
        # _CLASSIFIER_HINTS is ordered most-specific first, and each classifier
        # contributes at most one label, so "Topic :: Security :: Cryptography"
        # yields "crypto" rather than both "crypto" and the broader "security".
        for classifier in classifiers:
            text = str(classifier)
            for needle, label in _CLASSIFIER_HINTS:
                if text.startswith(needle):
                    hits.append(label)
                    break
        if hits:
            return sorted(set(hits))

        haystack = " ".join(
            str(pypi_info.get(field) or "") for field in ("keywords", "summary")
        ).lower()
        for needle, label in _KEYWORD_HINTS:
            if needle in haystack:
                hits.append(label)
        return sorted(set(hits))


@lru_cache(maxsize=1)
def load_exposure_map(path: str | None = None) -> ExposureMap:
    target = Path(path) if path else DATA_FILE
    with target.open("rb") as fh:
        return ExposureMap(tomllib.load(fh))
