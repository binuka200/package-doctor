"""Repository metadata via ecosyste.ms.

Chosen over the GitHub API deliberately: GitHub allows 60 unauthenticated
requests an hour, which a single real lockfile exhausts immediately. ecosyste.ms
serves the same fields at 5,000/hour with no key, so the tool works out of the
box with no token setup.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import quote

from .client import Client
from .pypi import parse_ts

REPO_API = "https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/{slug}"


class RepoInfo:
    __slots__ = ("archived", "pushed_at", "open_issues", "url", "found")

    def __init__(
        self,
        found: bool,
        archived: bool | None = None,
        pushed_at: dt.datetime | None = None,
        open_issues: int | None = None,
        url: str | None = None,
    ):
        self.found = found
        self.archived = archived
        self.pushed_at = pushed_at
        self.open_issues = open_issues
        self.url = url


class EcosystemsSource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch_repo(self, slug: str) -> RepoInfo:
        data = await self.client.get_json(
            REPO_API.format(slug=quote(slug, safe="")), cache_key=f"ecosystems:repo:{slug.lower()}"
        )
        if not isinstance(data, dict) or Client.is_missing(data):
            return RepoInfo(found=False, url=f"https://github.com/{slug}")
        return RepoInfo(
            found=True,
            archived=data.get("archived"),
            pushed_at=parse_ts(data.get("pushed_at")),
            open_issues=data.get("open_issues_count"),
            url=data.get("html_url") or f"https://github.com/{slug}",
        )
