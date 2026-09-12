"""Measure package-doctor against real repositories.

Clones each repository shallowly, scans it, and checks the two layers that can
be checked mechanically:

* **advisory matching** - for every pinned (package, version) pair, whether the
  advisories the tool reports as affecting that version agree with OSV's own
  version-scoped ``querybatch`` answer, compared after collapsing GHSA/PYSEC
  aliases to their CVE;
* **reachability** - whether every reported import site names a line that
  really imports that distribution.

It then dumps every *act on these* verdict with its evidence, because the
verdict layer is a judgement and the only honest check is reading them.

    python research/evaluate_repos.py --repos research/eval-repos.txt --work /tmp/pd-eval

Idempotent: clones and scans already present are reused. The OSV answers are
cached in the work directory, so re-measuring after a change costs a rescan
and nothing else.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from package_doctor.sources.pypi import normalise
from package_doctor.sourcescan import MODULE_TO_DIST

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def clone(repo: str, dest: Path) -> None:
    if dest.exists():
        return
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"https://github.com/{repo}.git", str(dest)],
        check=False,
    )


def scan(root: Path, out: Path) -> dict | None:
    if not out.exists():
        subprocess.run(
            ["package-doctor", "scan", "--json", "-o", str(out), "--fail-on", "never",
             "--max-packages", "5000"],
            cwd=root, capture_output=True, text=True, timeout=1800, check=False,
        )
    return json.load(open(out)) if out.exists() else None


def osv_truth(pairs: list[tuple[str, str]], cache: Path) -> dict[tuple[str, str], set[str]]:
    truth: dict[tuple[str, str], set[str]] = {}
    if cache.exists():
        with cache.open() as fh:
            truth = {tuple(k.split("@@")): set(v) for k, v in json.load(fh).items()}
    todo = [k for k in pairs if k not in truth]
    for start in range(0, len(todo), 500):
        batch = todo[start:start + 500]
        body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                            for n, v in batch]}
        req = urllib.request.Request(
            OSV_BATCH, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        results = json.load(urllib.request.urlopen(req, timeout=180))["results"]
        for key, r in zip(batch, results, strict=True):
            ids = {v["id"] for v in r.get("vulns", [])}
            token = r.get("next_page_token")
            while token:
                page = {"queries": [{"package": {"name": key[0], "ecosystem": "PyPI"},
                                     "version": key[1], "page_token": token}]}
                req = urllib.request.Request(
                    OSV_BATCH, data=json.dumps(page).encode(),
                    headers={"Content-Type": "application/json"},
                )
                r2 = json.load(urllib.request.urlopen(req, timeout=180))["results"][0]
                ids |= {v["id"] for v in r2.get("vulns", [])}
                token = r2.get("next_page_token")
            truth[key] = ids
        time.sleep(1)
    with cache.open("w") as fh:
        json.dump({"@@".join(k): sorted(v) for k, v in truth.items()}, fh)
    return truth


def alias_map(cache_db: Path) -> dict[str, str]:
    """id -> canonical id (the CVE when there is one), from the tool's own cache."""
    import sqlite3

    out: dict[str, str] = {}
    if not cache_db.exists():
        return out
    db = sqlite3.connect(str(cache_db))
    for (_, body) in db.execute("SELECT key, body FROM entries WHERE key LIKE 'osv:%'"):
        for v in json.loads(body)["body"].get("vulns", []):
            ids = {v["id"], *v.get("aliases", [])}
            canon = sorted(i for i in ids if i.startswith("CVE-")) or [v["id"]]
            for i in ids:
                out[i] = canon[0]
    return out


def check_site(root: Path, name: str, site: str) -> str:
    rel, _, line = site.rpartition(":")
    path = root / rel
    if not path.is_file():
        return "file not found"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if int(line) > len(lines):
        return "line out of range"
    src = lines[int(line) - 1]
    m = re.match(r"\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", src)
    if not m:
        return "not an import"
    if m.group(1):
        mods = [m.group(1)]
    else:
        mods = [x.strip().split(" as ")[0] for x in m.group(2).split(",")]
    tops = {x.split(".")[0] for x in mods}
    cands: set[str] = set()
    for t in tops:
        for candidate in (t, MODULE_TO_DIST.get(t, t), MODULE_TO_DIST.get(t.lower(), t)):
            cands.add(normalise(candidate))
    return "ok" if normalise(name) in cands else "other module"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=Path, required=True, help="one owner/name[:subdir] per line")
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument(
        "--cache-db", type=Path,
        default=Path.home() / ".cache" / "package-doctor" / "http-cache.sqlite3",
    )
    args = ap.parse_args()
    (args.work / "repos").mkdir(parents=True, exist_ok=True)
    (args.work / "out").mkdir(exist_ok=True)

    scans: dict[str, tuple[Path, dict]] = {}
    for line in args.repos.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        repo, _, sub = line.partition(":")
        name = repo.replace("/", "__")
        dest = args.work / "repos" / name
        clone(repo, dest)
        data = scan(dest / sub, args.work / "out" / f"{name}.json")
        if data is None:
            print(f"{repo}: no scan output")
            continue
        scans[name] = (dest / sub, data)

    total = sum(len(d["findings"]) for _, d in scans.values())
    counts: collections.Counter = collections.Counter()
    for _, d in scans.values():
        counts.update(f["verdict"] for f in d["findings"])
    print(f"\nrepositories scanned: {len(scans)}   packages: {total}   verdicts: {dict(counts)}")

    pairs: dict[tuple[str, str], set[str]] = {}
    for _, d in scans.values():
        for f in d["findings"]:
            if f["version"]:
                pairs.setdefault((f["name"], f["version"]), set()).update(
                    f["remediation"]["advisories"]["ids_affecting_current"]
                )
    keys = sorted(pairs)
    truth = osv_truth(keys, args.work / "osv_truth.json")
    alias = alias_map(args.cache_db)
    exact = 0
    for k in keys:
        t = {alias.get(i, i) for i in truth[k]}
        m = {alias.get(i, i) for i in pairs[k]}
        if t == m:
            exact += 1
        else:
            print(f"  disagree {k}: osv-only={sorted(t - m)} tool-only={sorted(m - t)}")
    print(f"advisory matching vs OSV: {exact}/{len(keys)} pinned pairs exact")

    sites: collections.Counter = collections.Counter()
    for root, d in scans.values():
        for f in d["findings"]:
            for site in f["reachability"]["sites"]:
                sites[check_site(root, f["name"], site)] += 1
    print(f"reachability: {dict(sites)}")

    acts = []
    for name, (_, d) in scans.items():
        for f in d["findings"]:
            if f["verdict"] == "act":
                acts.append({"repo": name, "package": f["name"], "version": f["version"],
                             "exposure": f["exposure"]["categories"],
                             "reasons": [r["claim"] for r in f["reasons"]]})
    with (args.work / "acts.json").open("w") as fh:
        json.dump(acts, fh, indent=1)
    print(f"act verdicts: {len(acts)} -> {args.work / 'acts.json'} (read them)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
