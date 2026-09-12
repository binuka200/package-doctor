"""Orchestration: gather signals per package, then assess."""

from __future__ import annotations

import asyncio
import datetime as dt

from .exposure import ExposureMap
from .models import Finding, Package, Remediation
from .risk import Thresholds, assess
from .sources.client import Client, ResponseTooLarge
from .sources.ecosystems import EcosystemsSource
from .sources.exploitability import ExploitabilitySource
from .sources.osv import OSVSource, build_history
from .sources.pypi import PyPISource, extract_github_repo


class Analyzer:
    def __init__(
        self,
        client: Client,
        exposure_map: ExposureMap,
        thresholds: Thresholds | None = None,
        skip_repo: bool = False,
    ):
        self.pypi = PyPISource(client)
        self.osv = OSVSource(client)
        self.repos = EcosystemsSource(client)
        self.exploit = ExploitabilitySource(client)
        self.exposure_map = exposure_map
        self.thresholds = thresholds or Thresholds()
        self.skip_repo = skip_repo

    async def _fetch_pypi(self, name: str) -> tuple[dict | None, str | None]:
        """PyPI metadata, or the reason there is none.

        "Not found" and "too large to read" are different facts, and the
        second is not the package's fault. Both are gaps, never bad scores.
        """
        try:
            data = await self.pypi.fetch(name)
        except ResponseTooLarge as exc:
            return None, f"PyPI response too large to read ({exc.limit // (1024 * 1024)} MB cap)"
        if data is None:
            return None, "not found on PyPI"
        return data, None

    async def analyze(self, package: Package, now: dt.datetime) -> Finding:
        (pypi_data, pypi_gap), vulns = await asyncio.gather(
            self._fetch_pypi(package.name),
            self.osv.fetch(package.name),
        )

        remediation = Remediation()

        if pypi_data is None:
            remediation.gaps.append(pypi_gap or "not found on PyPI")
            # Advisories come from OSV and do not depend on PyPI answering, so
            # they are still counted: metadata being unavailable must not make
            # a known-vulnerable pin look clean.
            remediation.advisories = build_history(package.name, vulns, {}, package.version)
            if remediation.advisories.cves_affecting_current:
                remediation.exploitability = await self.exploit.assess(
                    remediation.advisories.cves_affecting_current
                )
            exposure = self.exposure_map.lookup(package.name)
            finding = assess(
                package, exposure, remediation,
                now=now, thresholds=self.thresholds,
                known_stable=self.exposure_map.is_known_stable(package.name),
            )
            finding.error = pypi_gap
            return finding

        info = pypi_data.get("info") or {}
        releases = self.pypi.release_dates(pypi_data)
        latest_version, last_release = self.pypi.last_release(pypi_data)
        remediation.latest_version = latest_version
        remediation.last_release = last_release
        remediation.inactive_classifier = self.pypi.has_inactive_classifier(pypi_data)
        if last_release is None:
            remediation.gaps.append("no dated releases on PyPI")

        remediation.advisories = build_history(
            package.name, vulns, releases, package.version
        )

        # Score only what affects the pinned version. Historical CVEs are not
        # the user's problem and would drown the signal if included.
        if remediation.advisories.cves_affecting_current:
            remediation.exploitability = await self.exploit.assess(
                remediation.advisories.cves_affecting_current
            )

        slug = extract_github_repo(info)
        if slug and not self.skip_repo:
            repo = await self.repos.fetch_repo(slug)
            remediation.repo_url = repo.url
            if repo.found:
                remediation.repo_archived = repo.archived
                remediation.repo_last_push = repo.pushed_at
                remediation.open_issues = repo.open_issues
            else:
                remediation.gaps.append("repository metadata unavailable")
        elif slug:
            remediation.repo_url = f"https://github.com/{slug}"
        else:
            remediation.gaps.append("no source repository declared on PyPI")

        exposure = self.exposure_map.lookup(package.name, info)
        return assess(
            package,
            exposure,
            remediation,
            now=now,
            thresholds=self.thresholds,
            known_stable=self.exposure_map.is_known_stable(package.name),
        )

    async def analyze_all(
        self, packages: list[Package], now: dt.datetime, progress=None
    ) -> list[Finding]:
        async def one(pkg: Package) -> Finding:
            try:
                result = await self.analyze(pkg, now)
            except Exception as exc:
                result = assess(
                    pkg,
                    self.exposure_map.lookup(pkg.name),
                    Remediation(gaps=[f"lookup failed: {exc}"]),
                    now=now,
                    thresholds=self.thresholds,
                )
                result.error = str(exc)
            if progress is not None:
                progress()
            return result

        # Warm the KEV catalogue once rather than racing every package for it.
        await self.exploit.kev_catalogue()
        return list(await asyncio.gather(*(one(p) for p in packages)))
