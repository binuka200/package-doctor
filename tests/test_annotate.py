"""The second-reader instrument.

What matters here is that the sample is blind, the statistic is right, and
a disagreement is reported as what it is. The interactive session is not
tested - it is input() in a loop - but everything it writes and everything
that reads it is.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def annotate():
    spec = importlib.util.spec_from_file_location("annotate", ROOT / "research" / "annotate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


TINY_MAP = {
    "category": {
        "auth": {"label": "auth/session", "packages": ["pyjwt", {"name": "authlib", "why": "x"}]},
        "query": {"label": "query building", "packages": ["psycopg2", "pymysql", "asyncpg"]},
        "url": {"label": "url parsing", "packages": ["urllib3"]},
        "http": {"label": "http/network", "packages": ["urllib3", "requests"]},
    },
    "reviewed": {"not_exposed": [{"name": "six", "why": "finished"}, "click"]},
    "stable": {"packages": ["attrs"], "mature": []},
}


# --- Cohen's kappa ----------------------------------------------------------

def test_kappa_on_the_textbook_example(annotate):
    """50 items: 20 both-yes, 15 both-no, 5 A-yes/B-no, 10 A-no/B-yes.
    Observed 0.70, expected 0.50, kappa 0.40."""
    pairs = [("y", "y")] * 20 + [("n", "n")] * 15 + [("y", "n")] * 5 + [("n", "y")] * 10
    assert annotate.cohen_kappa(pairs) == pytest.approx(0.4)


def test_kappa_is_one_for_perfect_and_zero_for_chance(annotate):
    assert annotate.cohen_kappa([("a", "a"), ("b", "b"), ("c", "c")]) == 1.0
    # Each rater says yes half the time, independently: agreement is exactly chance.
    assert annotate.cohen_kappa([("y", "y"), ("y", "n"), ("n", "y"), ("n", "n")]) == 0.0


def test_kappa_edge_cases(annotate):
    assert annotate.cohen_kappa([]) is None
    assert annotate.cohen_kappa([("y", "y"), ("y", "y")]) == 1.0, "one label, no disagreement"
    assert annotate.cohen_kappa([("y", "n"), ("y", "n")]) == pytest.approx(0.0)


def test_kappa_is_described_in_the_usual_bands(annotate):
    assert "almost perfect" in annotate.describe_kappa(0.9)
    assert "substantial" in annotate.describe_kappa(0.7)
    assert "moderate" in annotate.describe_kappa(0.5)
    assert "poor" in annotate.describe_kappa(-0.1)
    assert "undefined" in annotate.describe_kappa(None)


# --- the sample -------------------------------------------------------------

def test_curator_decisions_come_from_all_three_lists(annotate):
    decisions = annotate.curator_decisions(TINY_MAP)
    assert decisions["urllib3"] == {"url", "http"}
    assert decisions["authlib"] == {"auth"}
    assert decisions["six"] == {annotate.NOT_EXPOSED}
    assert decisions["attrs"] == {annotate.NOT_EXPOSED}
    assert "numpy" not in decisions


def test_sample_is_deterministic_blind_and_free_of_duplicates(annotate):
    pool = [f"pkg{i}" for i in range(50)] + ["pyjwt"]  # pyjwt is curated: must be excluded
    a = annotate.stratified_sample(TINY_MAP, pool, size=12, seed=7)
    b = annotate.stratified_sample(TINY_MAP, pool, size=12, seed=7)
    assert a == b, "same seed, same sample"
    assert len(a) == len(set(a))
    assert all(isinstance(n, str) for n in a), "names only - no stratum, no answer"
    assert annotate.stratified_sample(TINY_MAP, pool, size=12, seed=8) != a


def test_sample_draws_from_every_stratum_and_every_category(annotate):
    pool = [f"pkg{i}" for i in range(50)]
    sample = set(annotate.stratified_sample(TINY_MAP, pool, size=20, seed=1))
    decisions = annotate.curator_decisions(TINY_MAP)
    curated = {n for n in sample if n in decisions}
    unreviewed = sample - curated
    assert unreviewed, "the unreviewed stratum is where the map's gaps are found"
    assert {"six", "click"} & sample or {"attrs"} & sample, "reviewed or stable names present"
    keys_hit = {k for n in curated for k in decisions[n] if k != annotate.NOT_EXPOSED}
    assert keys_hit == {"auth", "query", "url", "http"}, "every category contributes"


def test_without_a_dataset_the_unreviewed_share_goes_to_categories(annotate):
    sample = annotate.stratified_sample(TINY_MAP, [], size=10, seed=1)
    decisions = annotate.curator_decisions(TINY_MAP)
    assert all(n in decisions for n in sample)


# --- agreement --------------------------------------------------------------

def rows(*pairs: tuple[str, str], note: str = "") -> list[dict]:
    return [{"name": n, "decision": d, "note": note, "annotator": "alice"} for n, d in pairs]


def test_agreement_counts_binary_and_category_disagreements_separately(annotate):
    curator = annotate.curator_decisions(TINY_MAP)
    report = annotate.agreement(rows(
        ("pyjwt", "auth"),                       # agree
        ("psycopg2", "query"),                   # agree
        ("six", annotate.NOT_EXPOSED),           # agree
        ("requests", annotate.NOT_EXPOSED),      # boundary disagreement
        ("pymysql", "http"),                     # category disagreement
        ("urllib3", "url"),                      # multi-category: credited
        ("click", "skip"),                       # skipped
        ("numpy", "deserialization"),            # no curator opinion: a proposal
    ), curator)
    assert report["compared"] == 6
    assert report["skipped"] == 1
    assert [p["name"] for p in report["proposals"]] == ["numpy"]
    kinds = {d["name"]: d["kind"] for d in report["disagreements"]}
    assert kinds == {"requests": "boundary", "pymysql": "category"}
    assert report["confusion"] == {
        "both_exposed": 4, "both_not": 1, "curator_only": 1, "reader_only": 0,
    }
    assert report["binary_agreement"] == pytest.approx(5 / 6)
    assert 0 < report["binary_kappa"] < 1
    # More classes lower the chance-agreement floor, so the category kappa
    # can sit above the binary one; only its range is a fixed fact.
    assert -1 <= report["category_kappa"] <= 1


def test_names_are_normalised_before_comparison(annotate):
    curator = annotate.curator_decisions(TINY_MAP)
    report = annotate.agreement(rows(("PyJWT", "auth")), curator)
    assert report["compared"] == 1 and not report["disagreements"]


def test_the_report_prints_proposals_as_pasteable_entries(annotate, capsys):
    curator = annotate.curator_decisions(TINY_MAP)
    report = annotate.agreement(
        rows(("numpy", "deserialization"), note="np.load allow_pickle")
        + rows(("requests", "http")),
        curator,
    )
    annotate.print_agreement(report, "alice")
    out = capsys.readouterr().out
    assert '{ name = "numpy", why = "np.load allow_pickle" },' in out
    assert "kappa" in out


def test_the_real_map_yields_a_sample_with_no_answers_in_it(annotate, tmp_path):
    raw = annotate.load_raw_map()
    names = annotate.stratified_sample(raw, [], size=30, seed=3)
    assert 25 <= len(names) <= 30
    decisions = annotate.curator_decisions(raw)
    assert all(n in decisions for n in names)
    # What `sample` writes carries names and evidence only.
    doc = {"categories": annotate.category_keys(raw), "items": [{"name": n} for n in names]}
    text = json.dumps(doc)
    assert "not_exposed" not in text and '"stratum"' not in text
