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


# --- the widened map: integrity and the reviewed/unreviewed distinction -----

def _raw_map():
    import sys
    from package_doctor.exposure import DATA_FILE
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib
    with DATA_FILE.open("rb") as fh:
        return tomllib.load(fh)


def _norm(n: str) -> str:
    import re
    return re.sub(r"[-_.]+", "-", n).lower()


def test_no_package_is_both_exposed_and_reviewed_safe():
    """A contradiction here would make the verdict depend on lookup order."""
    raw = _raw_map()
    exposed = {
        _norm(p) for block in raw["category"].values() for p in block["packages"]
    }
    safe = {_norm(p) for p in raw["stable"]["packages"]}
    safe |= {_norm(p) for p in raw["reviewed"]["not_exposed"]}
    assert not (exposed & safe), f"listed as both exposed and safe: {sorted(exposed & safe)}"


def test_mature_entries_keep_their_exposure_category():
    """`stable.mature` is deliberately the one overlap: these packages are at a
    trust boundary and complete by design, so they keep the category and lose
    only the age-based reasoning."""
    raw = _raw_map()
    exposed = {_norm(p) for block in raw["category"].values() for p in block["packages"]}
    for name in raw["stable"].get("mature", []):
        assert _norm(name) in exposed, f"{name} is mature but has no exposure category"


def test_a_mature_library_is_exempt_from_age_but_not_from_facts():
    m = load_exposure_map()
    assert m.lookup("defusedxml").is_exposed, "defusedxml still parses untrusted XML"
    assert m.is_known_stable("defusedxml"), "age signals should not apply to it"


def test_command_line_parsers_are_not_trust_boundaries():
    """`argparse` was escalated because a "parser" keyword hint matched
    "command line parser". Parsing argv is not a trust boundary."""
    m = load_exposure_map()
    assert not m.lookup("argparse").is_exposed
    result = m.lookup("some-cli-tool", {
        "summary": "A command line parser for humans",
        "keywords": "cli parser parsing argv",
    })
    assert not result.is_exposed, "generic parser wording must not imply exposure"


def test_no_duplicate_entries_within_the_map():
    raw = _raw_map()
    for name, block in raw["category"].items():
        names = [_norm(p) for p in block["packages"]]
        assert len(names) == len(set(names)), f"duplicates in category.{name}"


def test_every_category_has_a_label_and_description():
    for name, block in _raw_map()["category"].items():
        assert block.get("label"), f"category.{name} has no label"
        assert block.get("description"), f"category.{name} has no description"


def test_reviewed_safe_suppresses_metadata_inference():
    """`xxhash` is a hash function, not cryptography. Without the reviewed list
    its classifiers would infer an exposure it does not have."""
    m = load_exposure_map()
    result = m.lookup("xxhash", {"classifiers": ["Topic :: Security :: Cryptography"]})
    assert not result.is_exposed
    assert result.confidence is Confidence.CURATED


def test_reviewed_is_distinguishable_from_never_looked_at():
    m = load_exposure_map()
    assert m.is_reviewed("tiktoken")
    assert not m.is_reviewed("some-package-nobody-has-heard-of")


def test_ml_model_loading_is_covered():
    """Loading pickle-based weights is arbitrary code execution, and is the
    boundary most often missed by scanners aimed at web stacks."""
    m = load_exposure_map()
    for name in ("torch", "transformers", "huggingface-hub", "joblib"):
        assert m.lookup(name).is_exposed, name


def test_map_covers_a_meaningful_share_of_common_packages():
    m = load_exposure_map()
    assert m.size > 300
    assert m.reviewed_size > 400


def test_packages_misclassified_on_a_real_repository_are_mapped():
    """Scanning a real Django project surfaced three gaps. nltk was the serious
    one: 82 advisories against the pinned version, six with no fix, including
    path traversal and arbitrary file overwrite in its model downloader - and
    it was reported as 'stale, not exposed / low priority'."""
    m = load_exposure_map()
    assert m.lookup("nltk").is_exposed, "nltk downloads and deserialises model artifacts"
    assert "query building" in m.lookup("django-filter").categories, (
        "django-filter builds ORM queries from user-supplied query strings"
    )
    assert m.lookup("drf-spectacular").is_exposed
    for name in ("nltk", "django-filter", "drf-spectacular"):
        assert m.lookup(name).confidence is Confidence.CURATED


def test_the_llm_agent_stack_is_mapped():
    """Scanning a real RAG project found langchain-core reporting "ok" while
    carrying 12 advisories against the pinned version, and langchain-community
    sitting in low-priority with an archived repository and an unfixed
    advisory. Document loaders fetch untrusted URLs and agents act on model
    output, so prompt injection is a trust boundary like any other."""
    m = load_exposure_map()
    for name in ("langchain", "langchain-core", "langchain-community", "langgraph",
                 "llama-index", "openai", "anthropic", "mcp", "tavily-python"):
        assert m.lookup(name).is_exposed, name
        assert m.lookup(name).confidence is Confidence.CURATED, name
    assert "llm/agent" in m.lookup("langchain").categories


def test_vector_stores_are_treated_as_databases():
    """chromadb had eight unfixed advisories and was reported as not exposed."""
    m = load_exposure_map()
    for name in ("chromadb", "qdrant-client", "pinecone-client", "weaviate-client"):
        assert "query building" in m.lookup(name).categories, name


def test_model_serving_infrastructure_is_mapped():
    """A 3,000-package bulk scan found the largest remediation gaps in the
    dataset - mlflow 36 unfixed, gradio 25, vllm 15, sglang 12 - sitting
    outside the map entirely. These accept untrusted requests and load model
    artifacts; they are servers, not libraries."""
    m = load_exposure_map()
    for name in ("mlflow", "gradio", "vllm", "sglang", "ray", "bentoml"):
        assert m.lookup(name).is_exposed, name


# --- the inference layer, after it was measured -----------------------------

def test_security_tooling_classifiers_do_not_imply_exposure():
    """`Topic :: Security` means "this is a security tool", not "this handles
    untrusted input". It was catching bandit, semgrep and pip-audit."""
    m = load_exposure_map()
    for summary in ("Static analysis for security", "Audit Python environments"):
        result = m.lookup("some-scanner", {
            "classifiers": ["Topic :: Security"], "summary": summary,
        })
        assert not result.is_exposed


def test_build_and_plotting_tools_are_not_inferred_as_exposed():
    """setuptools and wheel were 'archive extraction'; seaborn and pydeck were
    'file/media parsing'. None of them touch a trust boundary."""
    m = load_exposure_map()
    cases = [
        {"classifiers": ["Topic :: System :: Archiving :: Packaging"]},
        {"classifiers": ["Topic :: Multimedia :: Graphics"]},
        {"classifiers": ["Framework :: Django"], "summary": "pytest plugin for django"},
        {"classifiers": ["Topic :: Database"], "summary": "HDF5 for Python"},
    ]
    for info in cases:
        assert not m.lookup("some-package", info).is_exposed, info
