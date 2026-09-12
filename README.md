# package-doctor

**Finds the dependencies that sit at a trust boundary and have no one left to fix them.**

In late August 2026, Anthropic's coordinated disclosure programme reported 2,300
vulnerabilities across 392 open source projects. 421 had been patched upstream.

That ratio is the problem this tool measures. Discovery is becoming automated.
Remediation still needs a human to reproduce the issue, avoid regressions, cut a
release and support everyone downstream. Finding a thousand bugs does not produce
a thousand safe patches.

So the question worth asking about a dependency is not *"is it healthy?"* It is:

> **If a vulnerability lands in this package tomorrow, am I exposed, and is
> anyone home to fix it?**

## The two-axis model

Every other scanner in this space scores packages on one axis — how maintained
they look — and then has to explain why it flagged `six`. package-doctor uses two,
and only escalates when both fire.

**Axis 1 — Exposure.** Does this package routinely handle data an attacker can
influence? Authentication, session and token handling, file uploads, archive
extraction, deserialization, HTML parsing, query building, cryptography, URL
parsing, and model loading. This comes from a curated map in
[`exposure.toml`](src/package_doctor/data/exposure.toml), not from a heuristic.

It holds **625 packages across 13 categories**, curated against the 3,000
most-downloaded packages on PyPI — 85% of the top 100 has been reviewed one way
or the other, and Django, FastAPI/ML, document-processing and web-scraping stacks
all scan with zero unclassified packages. Anything outside it falls back to
classifier inference, which is marked `inferred` and flagged with `?` in output
so you can distrust it.

**Axis 2 — Remediation capacity.** If a fix were needed, would one ship?

Both must fire. `six` going quiet is not a finding, because `six` is not at a
trust boundary. `legacy-auth` going quiet is the whole point.

## Reachability

package-doctor also AST-parses your own source and reports **where** you import
each dependency:

```
EXPOSED + NO ONE HOME   act on these
pyjwt   2.9.0   auth/session        1 advisory with no published fix: PYSEC-2025-183
                                    imported by your code at api/auth.py:1
pillow  10.4.0  file/media parsing  pinned version affected by 34 advisories
                                    imported by your code at api/upload.py:2
```

Findings your code demonstrably imports sort to the top, because those are the
ones you can act on today. Import names are mapped to distributions, so
`from PIL import Image` is reported against `pillow` and `import jwt` against
`pyjwt`. Imports that only appear in test code are labelled as such.

### What "not imported" does not mean

**It does not mean unreachable, and it never lowers a verdict.** Your
dependencies call each other: a package absent from your source can still run on
every request. An import site is positive evidence that something is in play;
its absence is not evidence of anything, and the tool says so rather than
implying safety:

```
Reachability
  Imported by your code     no direct import found
    Not a safety finding: your dependencies call each other, so
    this can still run without appearing in your source.
```

A test asserts this invariant directly — the same package with an import site,
without one, and never checked all produce the same verdict.

Use `--src PATH` to point at source directories explicitly, or
`--no-reachability` to skip the scan.

## What it measures, and what it refuses to

Release age is a famously bad signal on its own — it cannot tell an abandoned
library from a finished one, or from a tool whose data updates server-side.
So it is never sufficient here. Signals are split in two:

**Authoritative** (any one is enough — these are facts, not inferences):

- the repository is archived
- the maintainer set `Development Status :: 7 - Inactive`
- an advisory exists with **no published fix anywhere**

**Weak** (two must agree before the tool says anything):

- no release in 2 years
- no commits in 18 months
- a history of fixing advisories only after public disclosure

### On "time to fix"

The obvious metric — days from advisory to patch — is wrong, and the data says
so. Under coordinated disclosure a healthy project ships the patched release at
or *before* the advisory goes public, so the median delta for well-run projects
is zero or negative. Measured across real packages, Django fixed 298 of 299
advisories at or before disclosure; requests, 15 of 16.

GitHub's advisory backfill makes a naive reading worse still: an advisory
written in 2022 for a fix shipped in 2012 produces a ten-year negative.

So package-doctor measures what the data actually supports:

- **never fixed** — advisories with no patched release. The strongest signal here.
- **fixed late** — how often a fix landed only after disclosure, and the median
  size of that window. PyYAML: 2 of 8, median 163 days.
- **fixed timely** — the healthy case, shown so a good project reads as good.

### Missing data is never a bad score

If a package has no advisory history, that is *unknown*, not *good*. If it
declares no repository, that is *unknown*, not *bad*. Findings with no signal go
in their own section and are never counted against a package. Conflating null
with zero is the most common flaw in package health tooling, and it is precisely
what makes those tools flag quiet infrastructure libraries as failures.

There is no aggregate health score anywhere in this tool. A single number is the
thing users cannot act on and maintainers cannot argue with.

## Install

```bash
pip install package-doctor
```

## Use

```bash
package-doctor scan
```

```
Dependency Risk Report   73 packages · 12 direct
from uv.lock, pyproject.toml

EXPOSED + NO ONE HOME    act on these
  legacy-auth   2.1.0   auth/session       repository is archived
                                           2 advisories with no published fix
  old-parser    1.7.4   html/xml parsing   marked Development Status :: 7 - Inactive

EXPOSED, MAINTAINED      watch
  requests      2.33.1  http/network, url parsing   15 of 16 past advisories
                                                    fixed at or before disclosure

STALE, NOT EXPOSED       low priority
  six           1.17.0  no boundary        reviewed as a finished utility
```

Then get the working behind any row:

```bash
package-doctor explain legacy-auth
```

### In CI

```bash
package-doctor scan --fail-on act
```

Exits `1` when anything lands in *act on these*, `0` otherwise. Use
`--fail-on watch` to be stricter, `--fail-on never` to report only.

```bash
package-doctor scan --json -o report.json
```

### Options

| Flag | Meaning |
| --- | --- |
| `--direct-only` | skip transitive dependencies |
| `--src PATH` | source directory to check for imports (repeatable) |
| `--no-reachability` | skip the import scan of your own source |
| `--show-ok` | also list packages with no concerns |
| `--offline-repo` | skip repository lookups (faster, fewer signals) |
| `--stale-release-days N` | tune the weak release-age signal (default 730) |
| `--no-cache` | bypass the local response cache |

Reads `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pyproject.toml` (PEP 621,
PEP 735 and Poetry), `Pipfile`, and `requirements*.txt`.

## Data sources

All free, all unauthenticated, no token setup:

- [PyPI JSON API](https://pypi.org/) — release timeline, classifiers, repository URL
- [OSV](https://osv.dev/) — advisories, affected ranges, fixed versions
- [ecosyste.ms](https://ecosyste.ms/) — repository metadata, at 5,000 req/hour
  rather than GitHub's unauthenticated 60

Responses are cached in `~/.cache/package-doctor/` for 24 hours.

## The exposure map

[`exposure.toml`](src/package_doctor/data/exposure.toml) is the part of this tool
that cannot be scraped, and it is deliberately a plain data file so it can be
argued with. A package belongs in it when it:

1. parses, decodes, renders, verifies or transports data that commonly
   originates outside the trust boundary, **or**
2. makes an authentication or authorisation decision, **or**
3. constructs queries or commands from caller-supplied values.

"Popular" is not a criterion. Neither is "sounds security-adjacent" — `xxhash`
and `mmh3` are deliberately **not** in the crypto category, because they are not
cryptographic, and `tiktoken` tokenises text rather than issuing auth tokens.

### Reviewed-and-safe is not the same as unreviewed

The map carries a third list, `[reviewed] not_exposed`, recording packages a
human checked and decided are *not* at a trust boundary — each with a note
saying why the obvious guess is wrong. Without it, classifier inference fires on
exactly those names. It also means "we looked and it's fine" is distinguishable
in the data from "nobody has looked yet", which is the distinction the rest of
this tool is built on.

### Depth is not the same as breadth

Beyond the top few hundred, most packages genuinely belong in neither list: a
plotting library or a CLI helper needs no entry, and adding one would be noise.
So raw "percent of PyPI covered" is the wrong measure. The one that matters is
whether a real lockfile scans without gaps — which is why the map is curated
against download-ranked data and checked against whole stacks rather than grown
for its own sake.

### One boundary most scanners miss

`[category.ml_model]` covers `torch`, `transformers`, `huggingface-hub`,
`joblib` and friends. Loading pickle-based weights is arbitrary code execution,
and tools aimed at web stacks tend not to model it at all. On a typical ML
service this is where the findings are: as of writing, `torch` carries 14
advisories with no published fix and `transformers` carries 9.

PRs welcome — include the reasoning, not just the name.

## A note on tone

Being listed here is not an accusation. Most unmaintained packages are the work
of volunteers who gave what they could, and "no releases since 2021, repository
archived" is a fact that helps a user without indicting anyone. Findings are
worded that way on purpose. If you find output that reads as a judgement on a
maintainer rather than a description of risk, that is a bug — please report it.

## Background

The reasoning behind this tool is set out in
[Rethinking Dependency Maintenance in the Age of AI Vulnerability Research](https://medium.com/@binukajayaweera/rethinking-dependency-maintenance-in-the-age-of-ai-vulnerability-research-30c8d2f775a6).

## License

MIT
