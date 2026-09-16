"""The map audit, and the first batch of calls it prompted.

The audit reads advisories against answers the map already gives. What
matters is that silence is the only thing it reports: an advisory named in a
`why` is a decision, whichever way it went, and must not be flagged again.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from package_doctor.exposure import load_exposure_map

ROOT = Path(__file__).resolve().parents[1]

TINY_MAP = """
[category.llm_agent]
label = "llm/agent"
description = "x"
consequence = "prompt injection"
packages = [
  { name = "agentkit", why = "agents over model output" },
]

[category.remote_exec]
label = "remote access"
description = "x"
consequence = "code execution"
packages = [
  { name = "shellkit", why = "runs commands" },
]

[category.http]
label = "http/network"
description = "x"
consequence = "request forgery"
packages = [
  { name = "webkit-py", why = "an HTTP server" },
]

[category.deserialization]
label = "deserialization"
description = "x"
consequence = "code execution"
packages = []

[category.archive]
label = "archive extraction"
description = "x"
consequence = "file write"
packages = []

[stable]
packages = []
mature = []

[reviewed]
families = [
  { pattern = "agentkit-*", why = "integration shims" },
]
not_exposed = [
  { name = "barfmt", why = "progress bars" },
  { name = "explained", why = "GHSA-aaaa-bbbb-cccc is a local symlink race" },
]
"""


def vuln(ident, *cwes, aliases=()):
    return {
        "id": ident,
        "aliases": list(aliases),
        "summary": f"advisory {ident}",
        "database_specific": {"cwe_ids": list(cwes)},
    }


@pytest.fixture(scope="module")
def audit():
    spec = importlib.util.spec_from_file_location("audit_map", ROOT / "research" / "audit_map.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Its dataclasses resolve string annotations through sys.modules.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


@pytest.fixture
def view(audit, tmp_path):
    path = tmp_path / "exposure.toml"
    path.write_text(TINY_MAP, encoding="utf-8")
    return audit.MapView(path)


def kinds(findings):
    return [f.kind for f in findings]


def test_a_cleared_package_with_boundary_advisories_is_reported(audit, view):
    found = audit.audit_one(view, "barfmt", [vuln("GHSA-1111-2222-3333", "CWE-94")], False)
    assert kinds(found) == ["cleared with evidence"]
    assert found[0].suggests == "remote_exec"


def test_naming_the_advisory_is_the_decision_and_silences_it(audit, view):
    vulns = [vuln("GHSA-aaaa-bbbb-cccc", "CWE-59")]
    assert audit.audit_one(view, "explained", vulns, False) == []


def test_an_alias_counts_as_the_same_advisory(audit, view):
    vulns = [vuln("PYSEC-2026-1", "CWE-59", aliases=["GHSA-aaaa-bbbb-cccc"])]
    assert audit.audit_one(view, "explained", vulns, False) == []


def test_input_only_weaknesses_are_not_evidence(audit, view):
    assert audit.audit_one(view, "barfmt", [vuln("GHSA-1111-2222-3333", "CWE-1333")], False) == []


def test_a_worse_consequence_in_the_advisories_is_reported(audit, view):
    found = audit.audit_one(view, "agentkit", [vuln("GHSA-1111-2222-3333", "CWE-502")], False)
    assert kinds(found) == ["understated consequence"]
    assert "code execution" in found[0].suggests


def test_a_milder_or_equal_consequence_is_not(audit, view):
    # SSRF is request forgery, milder than code execution: nothing to say.
    assert audit.audit_one(view, "shellkit", [vuln("GHSA-1111-2222-3333", "CWE-918")], False) == []


def test_path_traversal_does_not_argue_for_a_worse_consequence_by_default(audit, view):
    vulns = [vuln("GHSA-1111-2222-3333", "CWE-22")]
    assert audit.audit_one(view, "webkit-py", vulns, False) == []
    assert kinds(audit.audit_one(view, "webkit-py", vulns, True)) == ["understated consequence"]


def test_a_family_member_with_evidence_needs_an_entry_of_its_own(audit, view):
    found = audit.audit_one(view, "agentkit-cli", [vuln("GHSA-1111-2222-3333", "CWE-78")], False)
    assert kinds(found) == ["cleared with evidence"]
    assert found[0].recorded == "reviewed family agentkit-*"


def test_a_citation_the_package_does_not_carry_is_a_candidate(audit, view):
    found = audit.audit_one(view, "explained", [vuln("GHSA-9999-9999-9999", "CWE-1333")], False)
    assert kinds(found) == ["unknown citation"]
    assert found[0].recorded == "GHSA-AAAA-BBBB-CCCC"


def test_a_category_the_map_does_not_define_is_skipped_not_fatal(audit, tmp_path):
    path = tmp_path / "exposure.toml"
    path.write_text(TINY_MAP.replace("[category.deserialization]", "[unused]"), encoding="utf-8")
    view = audit.MapView(path)
    assert audit.audit_one(view, "agentkit", [vuln("GHSA-1111-2222-3333", "CWE-502")], False) == []


def test_withdrawn_advisories_are_not_evidence(audit, view):
    withdrawn = dict(vuln("GHSA-1111-2222-3333", "CWE-94"), withdrawn="2026-01-01T00:00:00Z")
    assert audit.audit_one(view, "barfmt", [withdrawn], False) == []


# --- the first batch it prompted -----------------------------------------------

def test_code_execution_the_advisories_describe_is_the_consequence_reported():
    """langchain's chains passed model output to exec(); llama-index's
    PandasQueryEngine did the same; langgraph's checkpointers rebuild objects
    from msgpack; semantic-kernel's vector store filters and smolagents'
    sandbox were code execution; pillow's ImageMath.eval ran code from its
    environment argument. Each was sorting as its milder category."""
    m = load_exposure_map()
    for name in ("langchain", "langchain-community", "langgraph", "llama-index",
                 "llama-index-core", "semantic-kernel", "smolagents", "pillow"):
        assert m.lookup(name).consequence == "code execution", name


def test_advisories_that_stopped_short_of_code_execution_do_not_escalate():
    """langchain-core's serialization injection revives objects only within
    LangChain's namespaces, and its template flaw is attribute access; the
    audit prompted both and reading them said no. The reason is recorded."""
    m = load_exposure_map()
    core = m.lookup("langchain-core")
    assert core.consequence != "code execution"
    assert "GHSA-c67j-w6g6-q2cm" in (m.why("langchain-core") or "")
    assert m.lookup("uvicorn").consequence == "request forgery"
    assert "ANSI escape" in (m.why("uvicorn") or "")


def test_a_family_member_with_its_own_advisory_is_decided_explicitly():
    m = load_exposure_map()
    assert not m.lookup("llama-index-cli").is_exposed
    assert "GHSA-g99h-56mw-8263" in (m.why("llama-index-cli") or "")


def test_citations_name_advisories_that_exist():
    """babel cited CVE-2021-20095 and diskcache GHSA-r8gq-9x9w-jcpg; OSV has
    neither. The advisories they meant are CVE-2021-42771 and
    GHSA-w8v5-vhqr-4h9v."""
    m = load_exposure_map()
    assert "CVE-2021-42771" in (m.why("babel") or "")
    assert "CVE-2021-20095" not in (m.why("babel") or "")
    assert "GHSA-w8v5-vhqr-4h9v" in (m.why("diskcache") or "")


def test_the_second_batch_escalations_follow_what_the_advisories_reached():
    """chromadb loaded a caller-named model repository with trust_remote_code
    before authentication; pdfminer.six let a PDF name the pickle file its CMap
    loader opens; Airflow's serialized DAGs and XComs ran code in processes its
    security model keeps DAG authors out of; litellm and haystack rendered
    user-supplied Jinja2 unsandboxed. Signature verifiers are an
    authentication decision: starkbank-ecdsa's forgery authenticated as any
    user, signxml verifies SAML assertions."""
    m = load_exposure_map()
    for name in ("chromadb", "pdfminer-six", "apache-airflow", "litellm", "haystack-ai",
                 "langchain-experimental", "open-webui"):
        assert m.lookup(name).consequence == "code execution", name
    for name in ("ecdsa", "rsa", "starkbank-ecdsa", "signxml", "mcp", "mitmproxy", "fastmcp"):
        assert "auth/session" in m.lookup(name).categories, name
    assert m.lookup("thrift").consequence == "data access"


def test_tls_verification_inside_a_transport_stays_under_http():
    """Certificate checks in urllib3, aiohttp and twisted's clients are part of
    the transport; crypto holds the trust roots (certifi, truststore, pyopenssl).
    The advisories are cited so the audit does not raise them again."""
    m = load_exposure_map()
    for name in ("urllib3", "aiohttp", "twisted"):
        assert "crypto" not in m.lookup(name).categories, name
        assert "TLS verification inside a transport" in (m.why(name) or ""), name


def test_advisories_mislabelled_or_out_of_scope_are_recorded_not_acted_on():
    m = load_exposure_map()
    # A GitHub Actions workflow in the server's repository, filed against the client.
    assert "GitHub Actions workflow" in (m.why("text-generation") or "")
    assert m.lookup("text-generation").consequence == "prompt injection"
    # One 2014 advisory does not make code execution Django's representative outcome.
    assert m.lookup("django").consequence == "account takeover"
    assert "GHSA-rvq6-mrpv-m6rm" in (m.why("django") or "")


def test_a_why_does_not_point_at_an_entry_that_does_not_exist():
    """open-webui's reasons said it was listed under auth; it never was."""
    m = load_exposure_map()
    assert "auth/session" not in m.lookup("open-webui").categories
    assert "listed under auth" not in (m.why("open-webui") or "")
