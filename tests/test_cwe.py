"""Reading advisories for evidence of a trust boundary.

The mapping is a hint for a human reviewer. What the tests pin down is the
distinction it exists to draw: a weakness that only occurs in code handling
attacker-shaped data (deserialization, injection, traversal, authentication)
argues for a category; one that merely needs input to trigger (a slow regex,
an out-of-bounds read) argues for nothing in particular.
"""

from __future__ import annotations

from package_doctor.cwe import STRONG, WEAK, boundary_hints, cwe_ids


def ghsa(*cwes: str) -> dict:
    return {"id": "GHSA-x", "database_specific": {"cwe_ids": list(cwes)}}


def test_only_github_records_carry_cwe_ids():
    assert cwe_ids(ghsa("CWE-502")) == ["CWE-502"]
    assert cwe_ids({"id": "PYSEC-2024-1"}) == []
    assert cwe_ids({"database_specific": "not a dict"}) == []
    assert cwe_ids({"database_specific": {"cwe_ids": "CWE-502"}}) == []


def test_ids_are_normalised_and_junk_is_dropped():
    assert cwe_ids(ghsa(" cwe-79 ", "CWE-79", "not-a-cwe", 502)) == ["CWE-79"]


def test_strong_hints_name_the_category_and_the_evidence():
    strong, weak = boundary_hints([ghsa("CWE-502"), ghsa("CWE-89", "CWE-502")])
    assert strong == {"deserialization": ["CWE-502"], "query": ["CWE-89"]}
    assert weak == []


def test_weak_hints_prove_only_that_input_is_parsed():
    strong, weak = boundary_hints([ghsa("CWE-1333"), ghsa("CWE-400")])
    assert strong == {}
    assert weak == ["CWE-1333", "CWE-400"]


def test_an_unknown_cwe_is_ignored_rather_than_guessed():
    assert boundary_hints([ghsa("CWE-9999")]) == ({}, [])


def test_the_two_tables_do_not_overlap_and_point_at_real_categories():
    from package_doctor.exposure import load_exposure_map

    assert not set(STRONG) & set(WEAK)
    labels = set(load_exposure_map()._labels)
    assert set(STRONG.values()) <= labels, set(STRONG.values()) - labels
    assert set(WEAK.values()) == {"input"}


def test_num2words_shaped_history_gives_no_hint():
    """Three unfixed advisories about a maintainer account compromise carry
    no CWE that says anything about input handling. The ranker must not
    promote it on count alone - that is the lesson recorded in the map."""
    assert boundary_hints([{"id": "PYSEC-1"}, {"id": "PYSEC-2"}, {"id": "PYSEC-3"}]) == ({}, [])
