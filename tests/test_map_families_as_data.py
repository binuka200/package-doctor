"""The reviewed-as-a-family rule is data, not a comment.

The map's header used to say that ``google-cloud-*``, ``types-*`` and ten
other prefixes had been reviewed as shelves, but nothing read that sentence:
``is_reviewed`` said no for every member, the suggestion tooling kept
proposing them, and the reviewed count left out 447 packages in the top
3,000 that had in fact been decided. The patterns now live in
``[reviewed] families`` with a reason each, and these tests pin down the
three things that make that safe: a pattern needs a wildcard and a reason,
an explicit entry always beats the pattern it falls under, and a member is
reported as reviewed with the family's reason attached.
"""

from __future__ import annotations

import pytest

from package_doctor.exposure import ExposureMap, families, load_exposure_map
from package_doctor.models import Confidence


def _map() -> ExposureMap:
    return ExposureMap({
        "category": {
            "auth": {
                "label": "auth/session",
                "packages": [{"name": "acme-providers-login", "why": "it is the auth manager"}],
            }
        },
        "reviewed": {
            "not_exposed": [{"name": "acme-providers-metrics", "why": "counts things"}],
            "families": [
                {"pattern": "acme-providers-*", "why": "generated wrappers over the transport"},
                {"pattern": "Types_*", "why": "typing stubs; no runtime code"},
            ],
        },
    })


def test_a_family_member_is_reviewed_and_not_exposed():
    m = _map()
    assert m.is_reviewed("acme-providers-storage")
    e = m.lookup("acme-providers-storage")
    assert not e.is_exposed
    assert e.confidence is Confidence.CURATED
    assert "acme-providers-*" in (e.note or "")
    assert e.why == "generated wrappers over the transport"
    assert m.why("acme-providers-storage") == "generated wrappers over the transport"


def test_patterns_match_normalised_names():
    m = _map()
    assert m.is_reviewed("types-requests")
    assert m.is_reviewed("Types.Requests")
    assert not m.is_reviewed("typesetting")


def test_an_explicit_entry_beats_the_family_it_falls_under():
    m = _map()
    exposed = m.lookup("acme-providers-login")
    assert exposed.is_exposed and exposed.categories == ["auth/session"]
    assert exposed.why == "it is the auth manager"
    cleared = m.lookup("acme-providers-metrics")
    assert not cleared.is_exposed
    assert cleared.why == "counts things"
    assert cleared.note == "reviewed: not at a trust boundary"


def test_a_name_outside_every_family_still_gets_no_opinion():
    m = _map()
    assert not m.is_reviewed("unrelated-thing")
    assert m.lookup("unrelated-thing").confidence is Confidence.NONE
    assert m.why("unrelated-thing") is None


def test_a_family_needs_a_wildcard_and_a_reason():
    with pytest.raises(ValueError, match="wildcard"):
        families([{"pattern": "exact-name", "why": "x"}])
    with pytest.raises(ValueError, match="reason"):
        families([{"pattern": "foo-*", "why": "  "}])
    with pytest.raises(ValueError, match="without a pattern"):
        families(["foo-*"])
    assert families(None) == []


# --- the real map -----------------------------------------------------------

def test_the_shelves_the_header_named_are_now_data():
    m = load_exposure_map()
    for name in ("google-cloud-speech", "types-toml", "pytest-xdist", "opentelemetry-sdk",
                 "llama-index-embeddings-openai", "mypy-boto3-s3", "sphinxcontrib-jquery",
                 "nvidia-cublas-cu12", "azure-mgmt-compute"):
        assert m.is_reviewed(name), name
        assert not m.lookup(name).is_exposed, name
        assert m.lookup(name).why, name
    assert m.family_count >= 10


def test_the_exceptions_to_a_family_are_explicit_entries():
    """The Airflow provider that is an authentication manager, the SQL
    provider with an injection advisory, and the storage client with a
    padding-oracle advisory are members of not-exposed families and are
    exposed anyway, because an entry with a reason beats a pattern."""
    m = load_exposure_map()
    assert "auth/session" in m.lookup("apache-airflow-providers-fab").categories
    assert "query building" in m.lookup("apache-airflow-providers-common-sql").categories
    assert m.lookup("google-cloud-storage").is_exposed
    assert m.lookup("google-cloud-aiplatform").is_exposed
    assert m.lookup("opentelemetry-instrumentation").is_exposed
    assert not m.lookup("opentelemetry-instrumentation-requests").is_exposed


def test_a_package_in_several_categories_keeps_every_reason():
    m = ExposureMap({
        "category": {
            "a": {"label": "llm/agent", "consequence": "prompt injection",
                  "packages": [{"name": "mlflow", "why": "what it is"}]},
            "b": {"label": "model loading", "consequence": "code execution",
                  "packages": [{"name": "mlflow", "why": "what broke"}]},
        }
    })
    e = m.lookup("mlflow")
    assert e.categories == ["llm/agent", "model loading"]
    assert e.consequence == "code execution"
    assert "what it is" in (e.why or "") and "what broke" in (e.why or "")
    real = load_exposure_map().why("mlflow") or ""
    assert "pickle" in real and "tracking server" in real
