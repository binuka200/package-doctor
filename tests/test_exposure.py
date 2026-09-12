from __future__ import annotations

from package_doctor.exposure import load_exposure_map
from package_doctor.models import Confidence


def test_map_loads_and_is_not_trivially_small():
    m = load_exposure_map()
    assert m.size > 200


def test_curated_lookups():
    m = load_exposure_map()
    assert "auth/session" in m.lookup("pyjwt").categories
    assert "crypto" in m.lookup("cryptography").categories
    assert "deserialization" in m.lookup("PyYAML").categories  # normalisation
    assert m.lookup("pyjwt").confidence is Confidence.CURATED


def test_stable_utilities_are_not_exposed():
    m = load_exposure_map()
    for name in ("six", "pytz", "typing-extensions"):
        assert not m.lookup(name).is_exposed
        assert m.is_known_stable(name)


def test_unknown_package_gets_no_opinion():
    m = load_exposure_map()
    result = m.lookup("some-package-nobody-has-heard-of")
    assert not result.is_exposed
    assert result.confidence is Confidence.NONE


def test_inference_from_classifiers_is_marked_as_inferred():
    m = load_exposure_map()
    result = m.lookup("unknown-thing", {"classifiers": ["Topic :: Security :: Cryptography"]})
    assert result.categories == ["crypto"]
    assert result.confidence is Confidence.INFERRED


def test_inference_does_not_fire_on_bland_metadata():
    m = load_exposure_map()
    result = m.lookup("unknown-thing", {
        "classifiers": ["Topic :: Terminals"],
        "summary": "Pretty terminal colours",
    })
    assert not result.is_exposed
