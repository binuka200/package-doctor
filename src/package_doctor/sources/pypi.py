"""PyPI JSON API: release timeline, classifiers, and repository discovery."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any
from urllib.parse import quote

from .client import Client

PYPI_JSON = "https://pypi.org/pypi/{name}/json"

#: PyPI's own response cap, above the client default.
#:
#: The JSON body lists every file of every release and is the one response in
#: this tool that grows without bound: pydantic-core was 12.6 MB at the time
#: of writing and gaining about 3 MB a year. The body is reduced to a few
#: kilobytes the moment it is parsed, so the cost of a larger cap is transient
#: memory and nothing else - but the parsed form of JSON is several times the
#: size of the bytes, which is why this stops at 64 MB rather than going
#: higher.
PYPI_MAX_RESPONSE_BYTES = 64 * 1024 * 1024

#: Fields of ``info`` the tool reads. Everything else - the long description,
#: the author list, the URL table for every file - is dropped before caching.
_INFO_FIELDS = (
    "name", "version", "summary", "keywords", "classifiers",
    "project_urls", "home_page", "download_url", "requires_python",
)

_GITHUB_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s#?]+)", re.I)

#: Keys in ``project_urls`` that plausibly point at the source repository,
#: in descending order of how much we trust them.
_REPO_URL_KEYS = (
    "source", "source code", "repository", "code", "github",
    "homepage", "home", "project-urls", "bug tracker", "issues", "tracker",
)


def parse_ts(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalise(name: str) -> str:
    """PEP 503 normalisation, so ``Flask_Login`` and ``flask-login`` agree."""
    return re.sub(r"[-_.]+", "-", name).lower()


def extract_github_repo(info: dict[str, Any]) -> str | None:
    """Find a GitHub ``owner/name`` from PyPI metadata.

    Fewer than two thirds of PyPI projects declare a repository at all, so a
    miss here is common and must be reported as a gap, never as a bad score.
    """
    candidates: list[str] = []
    urls = info.get("project_urls") or {}
    if isinstance(urls, dict):
        ordered = sorted(
            urls.items(),
            key=lambda kv: next(
                (i for i, k in enumerate(_REPO_URL_KEYS) if k == kv[0].strip().lower()),
                len(_REPO_URL_KEYS),
            ),
        )
        candidates.extend(v for _, v in ordered if isinstance(v, str))
    for key in ("home_page", "download_url"):
        val = info.get(key)
        if isinstance(val, str):
            candidates.append(val)

    for url in candidates:
        m = _GITHUB_RE.search(url)
        if m:
            owner, repo = m.group(1), m.group(2)
            if repo.endswith(".git"):
                repo = repo[:-4]
            if owner.lower() in {"sponsors", "orgs"}:
                continue
            return f"{owner}/{repo}"
    return None


def reduce_pypi(data: Any) -> Any:
    """Keep only what the tool reads from a PyPI response.

    The JSON API returns every file of every release, with digests, download
    counts and URLs - for a project with two thousand releases that is several
    megabytes, and the tool reads two fields per file: when it was uploaded
    and whether it was yanked. Cached whole, a hundred packages cost over a
    hundred megabytes, which put any real lockfile past the cache's size limit
    and into a cycle of pruning fresh entries and refetching them.

    Each release collapses to a single synthetic file carrying the earliest
    upload time and whether *every* file was yanked, which is exactly what
    ``release_dates`` and ``last_release`` compute from the full list. The
    shape is kept, so the readers and their tests need no special case, and a
    release with no files stays an empty list because both readers skip that.
    """
    if not isinstance(data, dict):
        return data
    info = data.get("info")
    slim_info = (
        {k: info.get(k) for k in _INFO_FIELDS if k in info}
        if isinstance(info, dict) else {}
    )
    slim_releases: dict[str, list[dict[str, Any]]] = {}
    for version, files in (data.get("releases") or {}).items():
        if not isinstance(files, list):
            continue
        entries = [f for f in files if isinstance(f, dict)]
        if not entries:
            slim_releases[str(version)] = []
            continue
        # Earliest upload, chosen by parsed time rather than string order, and
        # kept as the original string so the reader parses it the same way.
        dated = [
            (ts, raw)
            for f in entries
            if isinstance(raw := f.get("upload_time_iso_8601"), str) and (ts := parse_ts(raw))
        ]
        earliest = min(dated)[1] if dated else None
        slim_releases[str(version)] = [{
            "upload_time_iso_8601": earliest,
            "yanked": all(f.get("yanked") for f in entries),
        }]
    return {"info": slim_info, "releases": slim_releases}


class PyPISource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch(self, name: str) -> dict[str, Any] | None:
        data = await self.client.get_json(
            # Quoted as defence in depth: names are validated on the way in,
            # and this keeps a future caller from reintroducing the problem.
            PYPI_JSON.format(name=quote(name, safe="")),
            # The key carries the shape version: entries written before the
            # response was reduced hold the full body, and must not be read
            # as if they were reduced or kept alive by being looked up.
            cache_key=f"pypi:v2:{normalise(name)}",
            reduce=reduce_pypi,
            max_bytes=PYPI_MAX_RESPONSE_BYTES,
        )
        if data is None or Client.is_missing(data):
            return None
        return data

    @staticmethod
    def release_dates(data: dict[str, Any]) -> dict[str, dt.datetime]:
        """Map version -> earliest upload time.

        Uses the earliest file in a release, since wheels for extra platforms
        can trail the original upload by weeks and would distort any timeline.
        """
        out: dict[str, dt.datetime] = {}
        for version, files in (data.get("releases") or {}).items():
            if not isinstance(files, list):
                continue
            stamps = [
                ts
                for f in files
                if isinstance(f, dict) and (ts := parse_ts(f.get("upload_time_iso_8601")))
            ]
            if stamps:
                out[version] = min(stamps)
        return out

    @staticmethod
    def last_release(data: dict[str, Any]) -> tuple[str | None, dt.datetime | None]:
        """Most recent *non-yanked* release, which is what a user would actually get."""
        best_version, best_date = None, None
        for version, files in (data.get("releases") or {}).items():
            if not isinstance(files, list) or not files:
                continue
            if all(isinstance(f, dict) and f.get("yanked") for f in files):
                continue
            stamps = [
                ts
                for f in files
                if isinstance(f, dict) and (ts := parse_ts(f.get("upload_time_iso_8601")))
            ]
            if not stamps:
                continue
            date = min(stamps)
            if best_date is None or date > best_date:
                best_version, best_date = version, date
        return best_version, best_date

    @staticmethod
    def has_inactive_classifier(data: dict[str, Any]) -> bool:
        classifiers = (data.get("info") or {}).get("classifiers") or []
        return any("Development Status :: 7 - Inactive" in c for c in classifiers)
