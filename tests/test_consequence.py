"""The deserialization split, and the consequence vocabulary behind it.

Two commitments are tested. The first is that "deserialization" means
pickle-class - loaders that can instantiate arbitrary objects - and that
plain data parsers live elsewhere, because a stale pickle loader and a
stale JSON parser are not the same finding. The second is that the
consequence attached to each category stays a word: it orders findings
with the same evidence and it is shown to the reader, and it never becomes
a number or moves a verdict.
"""

from __future__ import annotations

import datetime as dt

import pytest
from rich.console import Console

from package_doctor.exposure import (
    CONSEQUENCE_ORDER,
    ExposureMap,
    consequence_rank,
    load_exposure_map,
)
from package_doctor.models import (
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Package,
    Remediation,
    Verdict,
)
from package_doctor.report import _sort_key, render, render_explain, to_dict
from package_doctor.risk import assess

NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)


# --- the split --------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "pyyaml", "ruamel-yaml", "dill", "cloudpickle", "joblib", "jsonpickle", "numpy",
    "pyarrow", "nltk", "celery", "rq", "diskcache", "apscheduler", "hydra-core",
])
def test_object_loaders_are_deserialization(name):
    e = load_exposure_map().lookup(name)
    assert e.categories == ["deserialization"], name
    assert e.consequence == "code execution"


@pytest.mark.parametrize("name", [
    "orjson", "ujson", "simplejson", "msgpack", "msgspec", "protobuf", "fastavro",
    "cbor2", "bson", "chardet", "charset-normalizer", "python-dateutil", "jsonschema",
    "pydantic", "marshmallow", "cattrs", "strictyaml",
])
def test_data_format_parsers_are_data_parsing(name):
    e = load_exposure_map().lookup(name)
    assert e.categories == ["data parsing"], name
    assert e.consequence == "denial of service"


def test_every_deserialization_entry_now_says_why():
    """The split was made by reading each loader; the reading is recorded."""
    m = load_exposure_map()
    raw = m._by_package
    missing = [n for n, labels in raw.items() if labels == ["deserialization"] and not m.why(n)]
    assert not missing, missing


def test_the_two_categories_do_not_overlap():
    m = load_exposure_map()
    both = [n for n, labels in m._by_package.items()
            if "deserialization" in labels and "data parsing" in labels]
    assert not both, both


# --- the vocabulary ---------------------------------------------------------

def test_every_category_names_a_consequence_from_the_vocabulary():
    m = load_exposure_map()
    for label in m._labels.values():
        assert m.consequence([label]) in CONSEQUENCE_ORDER, label


def test_an_unknown_consequence_is_refused_at_load():
    with pytest.raises(ValueError, match="not one of"):
        ExposureMap({"category": {"x": {"label": "x", "consequence": "badness",
                                        "packages": ["a"]}}})


def test_a_category_without_a_consequence_loads_and_ranks_last():
    m = ExposureMap({"category": {"x": {"label": "x", "packages": ["a"]}}})
    assert m.lookup("a").consequence is None
    assert consequence_rank(None) == len(CONSEQUENCE_ORDER)
    assert consequence_rank("nonsense") == len(CONSEQUENCE_ORDER)
    assert consequence_rank("code execution") == 0


def test_a_package_in_two_categories_carries_the_worse_consequence():
    m = ExposureMap({"category": {
        "url": {"label": "url parsing", "consequence": "request forgery", "packages": ["u"]},
        "rce": {"label": "remote access", "consequence": "code execution", "packages": ["u"]},
    }})
    assert m.lookup("u").consequence == "code execution"


def test_inferred_exposure_carries_a_consequence_too():
    e = load_exposure_map().lookup("some-unknown-thing", {
        "classifiers": ["Topic :: Security :: Cryptography"],
    })
    assert e.confidence is Confidence.INFERRED
    assert e.consequence == "data access"


# --- ordering, not scoring --------------------------------------------------

def stale(name: str, category: str, consequence: str) -> Finding:
    """Two years without a release, at a boundary, otherwise identical."""
    return assess(
        Package(name=name, version="1.0"),
        Exposure(categories=[category], confidence=Confidence.CURATED, consequence=consequence),
        Remediation(last_release=NOW - dt.timedelta(days=900), repo_archived=False,
                    repo_last_push=NOW - dt.timedelta(days=900)),
        now=NOW,
    )


def test_with_the_same_evidence_the_worse_consequence_sorts_first():
    loader = stale("cloudpickle", "deserialization", "code execution")
    parser = stale("ujson", "data parsing", "denial of service")
    assert loader.verdict is parser.verdict is Verdict.QUIET
    assert _sort_key(loader) < _sort_key(parser)
    # Name order would have put ujson last anyway; swap the names to be sure
    # it is the consequence deciding.
    loader.package.name, parser.package.name = "zzz", "aaa"
    assert _sort_key(loader) < _sort_key(parser)


def test_evidence_still_outranks_consequence():
    """A JSON parser with an advisory against the pinned version comes before
    a pickle loader with none: a concrete flaw beats an abstract class."""
    loader = stale("cloudpickle", "deserialization", "code execution")
    parser = stale("ujson", "data parsing", "denial of service")
    parser.remediation.advisories.affecting_current = 1
    parser.remediation.advisories.ids_affecting_current = ["GHSA-x"]
    assert _sort_key(parser) < _sort_key(loader)


def test_consequence_never_changes_a_verdict():
    for consequence in CONSEQUENCE_ORDER:
        healthy = assess(
            Package(name="p", version="1.0"),
            Exposure(categories=["x"], confidence=Confidence.CURATED, consequence=consequence),
            Remediation(last_release=NOW, repo_archived=False, repo_last_push=NOW),
            now=NOW,
        )
        assert healthy.verdict is Verdict.OK, consequence


def test_the_word_reaches_the_reader_and_the_json_and_nowhere_becomes_a_number(capsys):
    f = stale("cloudpickle", "deserialization", "code execution")
    f.reasons = [Evidence("no release in 2.5y")]
    render_explain(Console(width=100, force_terminal=False), f)
    out = capsys.readouterr().out
    assert "Consequence" in out and "code execution" in out
    payload = to_dict([f], [], NOW)
    assert payload["findings"][0]["exposure"]["consequence"] == "code execution"
    render(Console(width=100, force_terminal=False), [f], sources=["r.txt"], now=NOW)
    table = capsys.readouterr().out.lower()
    assert "score" not in table and "severity" not in table
