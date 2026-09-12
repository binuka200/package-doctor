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
    ("Topic :: Security :: Cryptography", "crypto"),
    ("Topic :: Security", "security"),
    ("Topic :: Internet :: WWW/HTTP :: Session", "auth/session"),
    ("Topic :: Internet :: WWW/HTTP :: WSGI", "http/network"),
    ("Topic :: Internet :: WWW/HTTP", "http/network"),
    ("Topic :: Text Processing :: Markup :: HTML", "html/xml parsing"),
    ("Topic :: Text Processing :: Markup :: XML", "html/xml parsing"),
    ("Topic :: Database", "query building"),
    ("Topic :: Multimedia :: Graphics", "file/media parsing"),
    ("Topic :: System :: Archiving", "archive extraction"),
    ("Framework :: Django", "web framework"),
    ("Framework :: Flask", "web framework"),
    ("Framework :: FastAPI", "web framework"),
)

#: Keyword fragments used only as a weak fallback, and only when a classifier
#: said nothing. Kept short on purpose: broad keyword matching is how these
#: tools start flagging things like `colorama` as a security concern.
_KEYWORD_HINTS: tuple[tuple[str, str], ...] = (
    ("oauth", "auth/session"),
    ("jwt", "auth/session"),
    ("saml", "auth/session"),
    ("ldap", "auth/session"),
    ("crypto", "crypto"),
    ("encryption", "crypto"),
    ("password", "auth/session"),
    ("deserializ", "deserialization"),
    ("sanitiz", "html/xml parsing"),
    ("parser", "parsing"),
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

    @property
    def size(self) -> int:
        return len(self._by_package)

    def is_known_stable(self, name: str) -> bool:
        """True for finished-not-abandoned utilities that age-based rules mis-flag."""
        return normalise(name) in self._stable

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
