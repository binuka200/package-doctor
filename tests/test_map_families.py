"""Packages of the same kind get the same answer.

The gaps a reviewer notices first are the inconsistent ones: psycopg2 in
the map and pyodbc not, kombu in and celery not, tokenizers in and
sentencepiece not. Each family below is a set of packages that do the same
job at the same boundary, and the test fails when one member has a
different answer from the others - mapped against unreviewed, or exposed
against cleared.

A family is not a claim that its members share a *category*: boto3 is
auth, google-cloud-storage is http, and both are exposed. It is a claim
that they are on the same side of the line. Adding a family here is the
cheapest way to make sure the next sibling gets decided.
"""

from __future__ import annotations

import pytest

from package_doctor.exposure import load_exposure_map

#: family -> (exposed?, members). Members are PyPI names.
FAMILIES: dict[str, tuple[bool, list[str]]] = {
    "sql drivers": (True, [
        "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient",
        "mysql-connector-python", "asyncpg", "aiomysql", "pyodbc", "cx-oracle",
        "oracledb", "pymssql", "clickhouse-driver", "cassandra-driver",
    ]),
    "document and key-value stores": (True, [
        "pymongo", "motor", "redis", "elasticsearch", "opensearch-py",
    ]),
    "orms": (True, ["sqlalchemy", "peewee", "tortoise-orm", "sqlmodel", "pony"]),
    "object storage clients": (True, [
        "google-cloud-storage", "azure-storage-blob", "minio", "s3fs", "gcsfs", "adlfs",
        "boto3",
    ]),
    "task queues": (True, ["celery", "kombu", "rq", "dramatiq", "huey"]),
    "git libraries": (True, ["gitpython", "dulwich", "pygit2"]),
    "ssh": (True, ["paramiko", "asyncssh", "fabric"]),
    "network devices": (True, ["netmiko", "napalm"]),
    "dns": (True, ["dnspython", "aiodns", "pycares"]),
    "realtime transports": (True, [
        "python-socketio", "python-engineio", "websockets", "websocket-client",
    ]),
    "tokenizer model files": (True, ["tokenizers", "sentencepiece"]),
    "xml": (True, ["lxml", "defusedxml", "xmltodict", "xmlschema", "untangle"]),
    "yaml": (True, ["pyyaml", "ruamel-yaml", "strictyaml"]),
    "markdown and html": (True, [
        "bleach", "nh3", "markdown", "mistune", "markdown2", "html5lib", "beautifulsoup4",
    ]),
    "templating": (True, ["jinja2", "mako", "chameleon"]),
    "archives": (True, ["py7zr", "rarfile", "patool", "libarchive-c"]),
    "images": (True, [
        "pillow", "opencv-python", "opencv-python-headless", "opencv-contrib-python",
        "imageio", "scikit-image", "wand",
    ]),
    "pdf": (True, ["pypdf", "pypdf2", "pdfminer-six", "pymupdf", "pikepdf", "pdfplumber"]),
    "jwt": (True, ["pyjwt", "python-jose", "authlib", "joserfc", "jwcrypto"]),
    "flask auth extensions": (True, [
        "flask-login", "flask-jwt-extended", "flask-security-too", "flask-httpauth",
        "flask-ipfilter",
    ]),
    "task and job queues over a wire protocol": (True, ["gearman3", "python3-gearman", "kombu"]),
    "packaging toolchain": (True, ["pip", "setuptools", "wheel"]),
    # Not exposed: the obvious guess is wrong for the same reason across the family.
    "test doubles": (False, [
        "fakeredis", "mongomock", "moto", "responses", "respx", "vcrpy", "aioresponses",
    ]),
    "cli frameworks": (False, ["click", "typer", "docopt", "fire"]),
    "documentation generators": (False, ["sphinx", "mkdocs", "mkdocs-material", "pdoc"]),
    "operator-controlled settings": (False, ["python-dotenv", "pydantic-settings", "environs"]),
}


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_every_member_of_a_family_is_decided_the_same_way(family):
    exposed, members = FAMILIES[family]
    m = load_exposure_map()
    undecided = [n for n in members if not m.is_reviewed(n)]
    assert not undecided, (
        f"{family}: {undecided} have no entry while their siblings do. Decide them "
        f"the same way, with a `why`, or take them out of the family."
    )
    wrong_side = [n for n in members if m.lookup(n).is_exposed != exposed]
    assert not wrong_side, (
        f"{family}: {wrong_side} are on the other side of the line from their "
        f"siblings (family says exposed={exposed})."
    )


def test_families_do_not_contradict_each_other():
    seen: dict[str, tuple[str, bool]] = {}
    for family, (exposed, members) in FAMILIES.items():
        for name in members:
            if name in seen and seen[name][1] != exposed:
                pytest.fail(f"{name} is exposed in {seen[name][0]} and not in {family}")
            seen[name] = (family, exposed)


def test_gitpython_is_at_a_boundary():
    """It was in the reviewed-and-cleared list as "git plumbing wrapper". Its
    thirty-odd advisories are command injection through git options and an
    untrusted search path: anything that clones a repository it was handed
    is at a boundary. Kept as a test because a wrong entry is worse than a
    missing one, and this one was wrong."""
    m = load_exposure_map()
    e = m.lookup("gitpython")
    assert e.is_exposed and "remote access" in e.categories
    assert "command injection" in (e.why or "")
