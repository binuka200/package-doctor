"""What a package's advisories say about where it sits.

An advisory count is a reason to look, never the answer - num2words reached
the top of the candidate list with three unfixed advisories that turned out
to be a maintainer account compromise. But the *kind* of weakness an
advisory records is different evidence. A deserialization flaw, an SQL
injection, a path traversal while extracting: each is a statement that the
package handles data an attacker could shape, made by whoever wrote the
advisory. That is close to the exposure map's own criterion, so it is the
best available signal for which unreviewed packages to read first.

GitHub-sourced OSV records carry CWE ids under ``database_specific``. The
mapping below turns them into the map's categories. It is a hint for a
human reviewer and nothing more: a CWE says what went wrong once, not what
the package is for, and it never becomes a curated entry on its own.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

#: CWE id -> exposure map category key. Strong: the weakness class only
#: occurs in code that handles attacker-shaped data, so a hit is a good
#: reason to expect the package belongs in the map.
STRONG: dict[str, str] = {
    # Object deserialization and code execution from data.
    "CWE-502": "deserialization",   # deserialization of untrusted data
    "CWE-915": "deserialization",   # improperly controlled modification of object attributes
    "CWE-1336": "templating",       # server-side template injection
    "CWE-94": "remote_exec",        # code injection
    "CWE-95": "remote_exec",        # eval injection
    "CWE-77": "remote_exec",        # command injection
    "CWE-78": "remote_exec",        # OS command injection
    "CWE-88": "remote_exec",        # argument injection
    # Query construction.
    "CWE-89": "query",              # SQL injection
    "CWE-90": "query",              # LDAP injection
    "CWE-643": "query",             # XPath injection
    "CWE-943": "query",             # NoSQL / data query injection
    "CWE-917": "query",             # expression language injection
    # Markup and document parsing.
    "CWE-79": "markup",             # cross-site scripting
    "CWE-80": "markup",             # basic XSS
    "CWE-91": "markup",             # XML injection
    "CWE-611": "markup",            # XXE
    "CWE-776": "markup",            # XML entity expansion
    "CWE-1236": "filetype",         # CSV / formula injection
    "CWE-434": "filetype",          # unrestricted upload of dangerous file type
    # Paths from data, usually archives.
    "CWE-22": "archive",            # path traversal
    "CWE-23": "archive",            # relative path traversal
    "CWE-36": "archive",            # absolute path traversal
    "CWE-59": "archive",            # link following
    "CWE-61": "archive",            # symlink following
    # Authentication and authorisation decisions.
    "CWE-287": "auth",              # improper authentication
    "CWE-288": "auth",              # authentication bypass via alternate path
    "CWE-290": "auth",              # authentication bypass by spoofing
    "CWE-294": "auth",              # capture-replay
    "CWE-303": "auth",              # incorrect implementation of authentication algorithm
    "CWE-306": "auth",              # missing authentication for critical function
    "CWE-307": "auth",              # improper restriction of authentication attempts
    "CWE-347": "auth",              # improper verification of cryptographic signature
    "CWE-384": "auth",              # session fixation
    "CWE-613": "auth",              # insufficient session expiration
    "CWE-639": "auth",              # authorization bypass through user-controlled key
    "CWE-862": "auth",              # missing authorization
    "CWE-863": "auth",              # incorrect authorization
    "CWE-1390": "auth",             # weak authentication
    # Cryptography and certificate handling.
    "CWE-295": "crypto",            # improper certificate validation
    "CWE-296": "crypto",            # improper following of a certificate chain
    "CWE-297": "crypto",            # improper validation of certificate with host mismatch
    "CWE-321": "crypto",            # hard-coded cryptographic key
    "CWE-326": "crypto",            # inadequate encryption strength
    "CWE-327": "crypto",            # broken or risky cryptographic algorithm
    "CWE-328": "crypto",            # reversible one-way hash
    "CWE-330": "crypto",            # insufficiently random values
    "CWE-338": "crypto",            # weak PRNG in a cryptographic context
    "CWE-1240": "crypto",           # risky cryptographic primitive
    # Requests built from data.
    "CWE-918": "http",              # server-side request forgery
    "CWE-601": "url",               # open redirect
    "CWE-113": "http",              # HTTP response splitting
    "CWE-444": "http",              # HTTP request smuggling
}

#: Weak: the weakness needs untrusted input to trigger, but says little about
#: what the package is for. A regular-expression denial of service is the
#: common case - it proves the package parses input, and nothing else.
WEAK: dict[str, str] = {
    "CWE-20": "input",              # improper input validation
    "CWE-400": "input",             # uncontrolled resource consumption
    "CWE-1333": "input",            # inefficient regular expression complexity
    "CWE-770": "input",             # allocation without limits
    "CWE-835": "input",             # infinite loop
    "CWE-674": "input",             # uncontrolled recursion
    "CWE-125": "input",             # out-of-bounds read
    "CWE-787": "input",             # out-of-bounds write
    "CWE-190": "input",             # integer overflow
    "CWE-119": "input",             # buffer errors
    "CWE-200": "input",             # information exposure
}

_CWE = re.compile(r"^CWE-\d+$")


def cwe_ids(vuln: dict[str, Any]) -> list[str]:
    """The CWE ids one OSV record carries, or none.

    Only GitHub-sourced records have them, under ``database_specific``.
    PYSEC records do not, which is why this is a hint and not a census.
    """
    specific = vuln.get("database_specific")
    if not isinstance(specific, dict):
        return []
    raw = specific.get("cwe_ids")
    if not isinstance(raw, list):
        return []
    return sorted({str(c).strip().upper() for c in raw if _CWE.match(str(c).strip().upper())})


def boundary_hints(vulns: Iterable[dict[str, Any]]) -> tuple[dict[str, list[str]], list[str]]:
    """Read a package's advisories for evidence of a trust boundary.

    Returns ``(strong, weak)``: strong maps each suggested category to the
    CWE ids that argued for it; weak is the list of CWE ids that only show
    the package parses input. Both are for a human to read, in that order.
    """
    strong: dict[str, list[str]] = {}
    weak: list[str] = []
    for vuln in vulns:
        for cwe in cwe_ids(vuln):
            category = STRONG.get(cwe)
            if category:
                if cwe not in strong.setdefault(category, []):
                    strong[category].append(cwe)
            elif cwe in WEAK and cwe not in weak:
                weak.append(cwe)
    return strong, weak
