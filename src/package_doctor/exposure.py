"""Axis 1: deciding whether a package sits at a trust boundary.

Two tiers, and the distinction is reported to the user rather than hidden:

* **curated** - a human put it in ``data/exposure.toml`` with a reason.
* **inferred** - guessed from PyPI classifiers and keywords for the long tail.

Anything else gets no opinion at all. An unknown exposure is reported as
unknown; it is never quietly treated as "safe" or as "risky".
"""

from __future__ import annotations

import sys
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

class ExposureMap:
    def __init__(self, data: dict[str, Any]):
        self._by_package: dict[str, list[str]] = {}
        self._labels: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}
        for key, block in (data.get("category") or {}).items():
            label = block.get("label", key)
            self._labels[key] = label
            self._descriptions[key] = block.get("description", "")
            for name in block.get("packages") or []:
                self._by_package.setdefault(normalise(str(name)), []).append(label)
        self._stable = {
            normalise(str(n)) for n in ((data.get("stable") or {}).get("packages") or [])
        }
        # Reviewed and deliberately not exposed. Distinct from "never looked at":
        # an entry here suppresses metadata inference, so a package cannot be
        # flagged just because its name or classifiers sound security-adjacent.
        self._reviewed_safe = {
            normalise(str(n)) for n in ((data.get("reviewed") or {}).get("not_exposed") or [])
        }
        # At a trust boundary AND deliberately finished. Keeps the exposure
        # category - these packages genuinely handle untrusted input - while
        # exempting them from age-based reasoning.
        self._mature = {
            normalise(str(n)) for n in ((data.get("stable") or {}).get("mature") or [])
        }

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

    def lookup(self, name: str, pypi_info: dict[str, Any] | None = None) -> Exposure:
        key = normalise(name)
        curated = self._by_package.get(key)
        if curated:
            return Exposure(categories=sorted(set(curated)), confidence=Confidence.CURATED)

        if key in self._stable:
            return Exposure(
                categories=[],
                confidence=Confidence.CURATED,
                note="reviewed: stable utility, not at a trust boundary",
            )

        if key in self._reviewed_safe:
            return Exposure(
                categories=[],
                confidence=Confidence.CURATED,
                note="reviewed: not at a trust boundary",
            )

        if pypi_info:
            inferred = self._infer(pypi_info)
            if inferred:
                return Exposure(
                    categories=inferred,
                    confidence=Confidence.INFERRED,
                    note="inferred from PyPI metadata, not human-reviewed",
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
