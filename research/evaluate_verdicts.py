"""Check the verdicts, not just the data under them, over an evaluate_repos.py run.

evaluate_repos.py checks the data layer - advisory matching and import sites.
This reads the same scans and checks each verdict's claim at its source, then
measures what a user would actually be asked to do:

* **exploited** - every CVE claimed is on today's CISA KEV list, and no pinned
  version OSV says a KEV CVE affects escaped the verdict;
* **upgrade** - the release named as the fix is clear of the advisories per
  OSV, is not a pre-release, and how often it is a new major when the pinned
  series already had a fix;
* **replace** - every archived repository confirmed by GitHub (``gh api``) and
  every Inactive classifier by PyPI;
* **triage** - vulnerable packages and advisories in, build failures out, and
  how much of what fails the build the project's own code imports.

    python research/evaluate_repos.py --repos research/eval-repos.txt --work /tmp/pd-eval
    python research/evaluate_verdicts.py --repos research/eval-repos.txt --work /tmp/pd-eval

Network answers (OSV, KEV, GitHub, PyPI) are cached in the work directory, so a
re-run after a change costs nothing but the reading.
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from evaluate_repos import alias_map, osv_truth
from packaging.version import InvalidVersion, Version

from package_doctor.sources.pypi import normalise

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"


def cached(path: Path, fetch):
    if path.exists():
        return json.loads(path.read_text())
    data = fetch()
    path.write_text(json.dumps(data))
    return data


def fill(path: Path, keys, fetch) -> dict:
    """A dict cached on disk, extended with any keys it does not have yet."""
    data = json.loads(path.read_text()) if path.exists() else {}
    for key in keys:
        if key not in data:
            data[key] = fetch(key)
    path.write_text(json.dumps(data))
    return data


def github_archived(url: str) -> str:
    slug = url.split("github.com/")[-1].strip("/")
    p = subprocess.run(["gh", "api", f"repos/{slug}", "--jq", ".archived"],
                       capture_output=True, text=True, check=False)
    if p.returncode != 0:
        return "unavailable"
    return "archived" if p.stdout.strip() == "true" else "live"


def pypi_inactive(name: str):
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as r:
            classifiers = json.load(r)["info"].get("classifiers") or []
    except Exception as exc:
        return f"error: {exc}"
    return any("7 - Inactive" in c for c in classifiers)


def smallest_fix(vuln: dict, name: str, pinned: Version) -> Version | None:
    """The lowest ``fixed`` event above the pinned version, in OSV's ranges."""
    fixes = []
    for affected in vuln.get("affected", []):
        if normalise(affected.get("package", {}).get("name", "")) != normalise(name):
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events", []):
                try:
                    fixed = Version(event["fixed"]) if "fixed" in event else None
                except InvalidVersion:
                    fixed = None
                if fixed is not None and fixed > pinned:
                    fixes.append(fixed)
    return min(fixes) if fixes else None


def reach(f: dict) -> str:
    r = f["reachability"]
    if not r["checked"]:
        return "not checked"
    if not r["sites"]:
        return "no direct import"
    return "tests only" if r["tests_only"] else "imported by app code"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=Path, required=True, help="one owner/name[:subdir] per line")
    ap.add_argument("--work", type=Path, required=True, help="evaluate_repos.py's --work")
    ap.add_argument(
        "--cache-db", type=Path, action="append",
        help="package-doctor cache(s) to read advisory aliases from "
             "(default: the user cache)",
    )
    args = ap.parse_args()
    work = args.work

    findings: list[tuple[str, dict]] = []
    for line in args.repos.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.partition(":")[0].replace("/", "__")
        out = work / "out" / f"{name}.json"
        if out.exists():
            findings += [(name, f) for f in json.loads(out.read_text())["findings"]]

    alias: dict[str, str] = {}
    for db in args.cache_db or [
        Path.home() / ".cache" / "package-doctor" / "http-cache.sqlite3"
    ]:
        alias.update(alias_map(db))

    def canon(ids) -> set[str]:
        return {alias.get(i, i) for i in ids}

    pairs = sorted({(f["name"], f["version"]) for _, f in findings if f["version"]})
    truth = osv_truth(pairs, work / "osv_truth.json")

    # --- exploited -------------------------------------------------------------
    kev = cached(work / "kev.json",
                 lambda: json.load(urllib.request.urlopen(KEV_URL, timeout=60)))
    kev_cves = {v["cveID"] for v in kev["vulnerabilities"]}
    exploited = [(n, f) for n, f in findings if f["verdict"] == "exploited"]
    unconfirmed = [(n, f["name"]) for n, f in exploited
                   if not set(f["remediation"]["exploitability"]["known_exploited"]) <= kev_cves
                   or not f["remediation"]["exploitability"]["known_exploited"]]
    missed = [(n, f["name"], f["version"], f["verdict"]) for n, f in findings
              if f["verdict"] != "exploited" and f["version"]
              and canon(truth.get((f["name"], f["version"]), ())) & kev_cves]
    print(f"exploited: {len(exploited)} findings, {len(exploited) - len(unconfirmed)} "
          f"confirmed on KEV; KEV-affected pins not marked exploited: {len(missed)}")
    for m in unconfirmed + missed:
        print("   ", m)

    # --- upgrade ---------------------------------------------------------------
    ups = [(n, f) for n, f in findings
           if f["verdict"] == "upgrade" and f["remediation"]["latest_version"]]
    targets = sorted({(f["name"], f["remediation"]["latest_version"]) for _, f in ups})
    target_truth = osv_truth(targets, work / "osv_truth_targets.json")
    still, pre = [], []
    for n, f in ups:
        latest = f["remediation"]["latest_version"]
        current = canon(f["remediation"]["advisories"]["ids_affecting_current"])
        if current & canon(target_truth[(f["name"], latest)]):
            still.append((n, f["name"], f["version"], latest))
        try:
            if Version(latest).is_prerelease or Version(latest).is_devrelease:
                pre.append((n, f["name"], latest))
        except InvalidVersion:
            pass
    print(f"upgrade: {len(ups)} findings; target still affected: {len(still)}; "
          f"target is a pre-release: {len(pre)}")
    for m in still + pre:
        print("   ", m)

    def major_jump(f: dict) -> bool:
        try:
            return Version(f["remediation"]["latest_version"]).major > Version(f["version"]).major
        except InvalidVersion:
            return False

    blocking_majors = [(n, f) for n, f in ups if f["blocks"] and major_jump(f)]
    ids = sorted({i for _, f in blocking_majors
                  for i in f["remediation"]["advisories"]["ids_affecting_current"]})
    vulns = fill(work / "osv_vulns.json", ids, lambda i: json.load(
        urllib.request.urlopen(OSV_VULN.format(i), timeout=60)))
    series: collections.Counter = collections.Counter()
    for _, f in blocking_majors:
        pinned = Version(f["version"])
        need = [smallest_fix(vulns[i], f["name"], pinned)
                for i in f["remediation"]["advisories"]["ids_affecting_current"]]
        if any(x is None for x in need):
            series["no fixed version recorded"] += 1
        elif max(need).major == pinned.major:
            series["the pinned series has a fix"] += 1
        else:
            series["a new major is needed"] += 1
    print(f"blocking upgrades to a new major: {len(blocking_majors)} -> {dict(series)}")

    # --- replace ---------------------------------------------------------------
    archived = sorted({f["remediation"]["repository"] for _, f in findings
                       if f["remediation"]["repo_archived"] and f["remediation"]["repository"]})
    gh = fill(work / "gh_archived.json", archived, github_archived)
    inactive = sorted({f["name"] for _, f in findings if f["remediation"]["inactive_classifier"]})
    py = fill(work / "pypi_inactive.json", inactive, pypi_inactive)
    print(f"archived: {len(archived)} repositories claimed, GitHub says "
          f"{dict(collections.Counter(gh[u] for u in archived))}")
    for u in archived:
        if gh[u] != "archived":
            print("   ", u, gh[u])
    print(f"inactive: {len(inactive)} claimed, "
          f"{sum(1 for p in inactive if py[p] is True)} confirmed by PyPI")

    # --- triage ----------------------------------------------------------------
    def count(key, rows) -> dict:
        return dict(collections.Counter(key(f) for _, f in rows))

    def affecting(f: dict) -> list[str]:
        return f["remediation"]["advisories"]["ids_affecting_current"]

    vulnerable = [(n, f) for n, f in findings if affecting(f)]
    blocks = [(n, f) for n, f in findings if f["blocks"]]
    advisories = sum(len(canon(affecting(f))) for _, f in vulnerable)
    boundary = lambda f: f["exposure"]["boundary"]  # noqa: E731
    print(f"\n{len({n for n, _ in findings})} repositories, {len(findings)} packages, "
          f"verdicts {count(lambda f: f['verdict'], findings)}")
    print(f"vulnerable packages: {len(vulnerable)} carrying {advisories} advisories, "
          f"in {len({n for n, _ in vulnerable})} repositories")
    print(f"fail the build: {len(blocks)} findings in {len({n for n, _ in blocks})} "
          f"repositories, {count(lambda f: f['verdict'], blocks)}")
    print(f"  of those: {count(reach, blocks)}, "
          f"{sum(1 for _, f in blocks if not f['direct'])} transitive")
    print(f"vulnerable but not blocking, by boundary: "
          f"{count(boundary, [(n, f) for n, f in vulnerable if not f['blocks']])}")
    print(f"exposure map: {count(boundary, findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
