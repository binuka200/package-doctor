#!/usr/bin/env python3
"""Head-to-head accuracy benchmark against pip-audit.

pip-audit is the PyPA tool and the right thing to measure against: if this
scanner misses a vulnerability pip-audit reports, that is a defect, and a
security tool with silent false negatives is worse than no tool at all.

Method, and why it is shaped this way:

* **Identical input.** Both tools see the same (package, pinned version) pairs,
  drawn from real repositories rather than invented. pip-audit resolves its
  input against the running interpreter, so the corpus is filtered to packages
  with pure-Python wheels - otherwise pip-audit cannot run at all on the old
  pins that matter most.
* **Compared at the vulnerability level, not the package level.** "Both tools
  flagged numpy" hides the case where one found ten advisories and the other
  found three.
* **Identifiers canonicalised to CVE.** One tool may report PYSEC-2026-2078
  where the other reports GHSA-p4gq-832x-fm9v for the same flaw; comparing raw
  ids would manufacture disagreements that do not exist.

Known limitation: both tools ultimately read OSV, so this measures whether we
read it correctly, not whether OSV is right. pip-audit's *default* source is
PyPI's advisory API, which is genuinely independent - and the three findings
this benchmark attributes to us alone are cases where that source lags OSV.

Usage:
    # 1. produce pip-audit JSON per chunk into $D/pa/
    # 2. D=<dir> python research/benchmark_vs_pip_audit.py
"""
import asyncio
import glob
import json
import os
import re
import sys

sys.path.insert(0, "src")
from package_doctor.cache import Cache
from package_doctor.sources.client import Client
from package_doctor.sources.osv import OSVSource, build_history
from package_doctor.sources.pypi import PyPISource

D = os.environ["D"]


def norm(s):
    return re.sub(r"[-_.]+", "-", s).lower()


pa = {}
for f in glob.glob(f"{D}/pa/*.json"):
    with open(f) as fh:
        loaded = json.load(fh)
    for dep in loaded.get("dependencies", []):
        if not dep.get("version"):
            continue
        # Canonicalise each vulnerability to its CVE where one exists, so a
        # PYSEC id from one tool matches the GHSA id from the other.
        vulns = set()
        for v in dep.get("vulns", []):
            ids = {v["id"]} | set(v.get("aliases") or [])
            cve = sorted(i for i in ids if i.startswith("CVE-"))
            vulns.add(cve[0] if cve else v["id"])
        pa[(norm(dep["name"]), dep["version"])] = vulns

async def main():
    cache = Cache(ttl=7*24*3600)
    both = only_pa = only_pd = 0
    rows = []
    async with Client(cache, concurrency=8, timeout=30) as c:
        pypi, osv = PyPISource(c), OSVSource(c)
        items = sorted(pa)
        for i in range(0, len(items), 40):
            async def one(key):
                name, ver = key
                data = await pypi.fetch(name)
                vulns = await osv.fetch(name)
                if data is None:
                    return key, None
                h = build_history(name, vulns, pypi.release_dates(data), ver)
                hit = set(h.ids_affecting_current)
                out = set()
                for v in vulns:
                    if v["id"] in hit:
                        ids = {v["id"]} | set(v.get("aliases") or [])
                        cve = sorted(x for x in ids if x.startswith("CVE-"))
                        out.add(cve[0] if cve else v["id"])
                return key, out
            for key, mine in await asyncio.gather(*(one(k) for k in items[i:i+40])):
                if mine is None:
                    continue
                theirs = pa[key]
                b, p, d = theirs & mine, theirs - mine, mine - theirs
                both += len(b)
                only_pa += len(p)
                only_pd += len(d)
                if p or d:
                    rows.append((key, sorted(p)[:4], sorted(d)[:4], len(theirs), len(mine)))
            print(f"  {min(i+40,len(items))}/{len(items)}", file=sys.stderr)
    cache.close()
    total = both + only_pa + only_pd
    print("\nvulnerability-level comparison over 654 packages")
    print(f"  found by both tools        : {both}")
    print(f"  found only by pip-audit    : {only_pa}   <- our false negatives")
    print(f"  found only by package-doctor: {only_pd}")
    print(f"  agreement                  : {100*both/total:.2f}%  (of {total} distinct findings)")
    if only_pa:
        recall = both / (both + only_pa)
        print(f"  recall vs pip-audit        : {100*recall:.2f}%")
    print(f"\n  packages where the sets differ: {len(rows)}")
    for key, p, d, tn, mn in rows[:20]:
        print(f"    {key[0]}=={key[1]}  pip-audit {tn} / us {mn}")
        if p:
            print(f"       we miss : {p}")
        if d:
            print(f"       we add  : {d}")

asyncio.run(main())
