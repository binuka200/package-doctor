"""Repository metadata via ecosyste.ms.

Chosen over the GitHub API deliberately: GitHub allows 60 unauthenticated
requests an hour, which a single real lockfile exhausts immediately. ecosyste.ms
serves the same fields at 5,000/hour with no key, so the tool works out of the
box with no token setup.
"""

from __future__ import annotations

import datetime as dt
import re
from urllib.parse import quote

from .client import Client, ResponseTooLarge
from .pypi import _GITHUB_RE, parse_ts

REPO_API = "https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/{slug}"

#: GitHub's per-branch commit feed. No key, no API rate limit, and the one
#: place to read the default branch's last commit without the GitHub API.
#:
#: It exists because ``pushed_at`` is not that date. GitHub advances it on a
#: push to *any* branch or tag - a Dependabot branch, a stale PR rebased -
#: so for flask-restful it read 2024-07 while the default branch's last
#: commit was 2023-05, fourteen months earlier. The bias runs one way,
#: toward looking maintained, and it can hide a dead package under the
#: threshold.
COMMITS_FEED = "https://github.com/{slug}/commits/{branch}.atom"
_FEED_UPDATED = re.compile(r"<entry>.*?<updated>([^<]+)</updated>", re.S)


class RepoInfo:
    __slots__ = ("archived", "pushed_at", "open_issues", "url", "found", "slug", "default_branch")

    def __init__(
        self,
        found: bool,
        archived: bool | None = None,
        pushed_at: dt.datetime | None = None,
        open_issues: int | None = None,
        url: str | None = None,
        slug: str | None = None,
        default_branch: str | None = None,
    ):
        self.found = found
        self.archived = archived
        #: GitHub's repository-level push time: any branch, any tag.
        self.pushed_at = pushed_at
        self.open_issues = open_issues
        self.url = url
        self.slug = slug
        self.default_branch = default_branch


class EcosystemsSource:
    def __init__(self, client: Client):
        self.client = client

    async def fetch_repo(self, slug: str) -> RepoInfo:
        try:
            data = await self.client.get_json(
                REPO_API.format(slug=quote(slug, safe="")),
                cache_key=f"ecosystems:repo:{slug.lower()}",
            )
        except ResponseTooLarge:
            data = None
        if not isinstance(data, dict) or Client.is_missing(data):
            return RepoInfo(found=False, url=f"https://github.com/{slug}")
        branch = data.get("default_branch")
        return RepoInfo(
            found=True,
            archived=data.get("archived"),
            pushed_at=parse_ts(data.get("pushed_at")),
            open_issues=data.get("open_issues_count"),
            url=data.get("html_url") or f"https://github.com/{slug}",
            slug=slug,
            default_branch=str(branch) if isinstance(branch, str) and branch else None,
        )

    async def last_commit(self, slug: str, branch: str) -> dt.datetime | None:
        """When the default branch last changed, from GitHub's commit feed."""
        def newest(text: str) -> str | None:
            match = _FEED_UPDATED.search(text)
            return match.group(1).strip() if match else None

        try:
            stamp = await self.client.get_text(
                COMMITS_FEED.format(slug=slug, branch=quote(branch, safe="")),
                cache_key=f"github:feed:{slug.lower()}:{branch}",
                reduce=newest,
                max_bytes=2 * 1024 * 1024,
                # The client asks for JSON by default, and GitHub obliges with
                # a JSON rendering of the commits page rather than the feed.
                headers={"Accept": "application/atom+xml"},
            )
        except ResponseTooLarge:
            return None
        return parse_ts(stamp) if isinstance(stamp, str) else None

    async def resolve_rename(self, slug: str) -> str | None:
        """The slug a renamed repository now lives at, or None.

        PyPI metadata keeps the address a project declared years ago; GitHub
        redirects the old one. ecosyste.ms does not follow that, so a moved
        repository read as "metadata unavailable" until this was asked.
        """
        target = await self.client.redirect_target(
            f"https://github.com/{slug}", cache_key=f"github:redirect:{slug.lower()}"
        )
        if not target:
            return None
        match = _GITHUB_RE.search(target)
        if not match:
            return None
        owner, repo = match.group(1), match.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        moved = f"{owner}/{repo}"
        return moved if moved.lower() != slug.lower() else None
