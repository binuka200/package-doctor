"""PyPI JSON API: release timeline, classifiers, and repository discovery."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

from .client import Client

PYPI_JSON = "https://pypi.org/pypi/{name}/json"

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


class PyPISource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch(self, name: str) -> dict[str, Any] | None:
        data = await self.client.get_json(
            PYPI_JSON.format(name=name), cache_key=f"pypi:{normalise(name)}"
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
