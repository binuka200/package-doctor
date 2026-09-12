# package-doctor

[![CI](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![Python](https://img.shields.io/pypi/pyversions/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

It holds **712 packages across 14 categories**, curated against the 3,000
most-downloaded packages on PyPI — 85% of the top 100 has been reviewed one way
or the other, and Django, FastAPI/ML, document-processing and web-scraping stacks
all scan with zero unclassified packages. Anything outside it falls back to
classifier inference, which is marked `inferred` and flagged with `?` in output
so you can distrust it.

**Axis 2 — Remediation capacity.** If a fix were needed, would one ship?

Both must fire. `six` going quiet is not a finding, because `six` is not at a
trust boundary. `legacy-auth` going quiet is the whole point.

## Which advisory first

"Affected by 35 advisories" is not a decision. A list that long gets skimmed and
then ignored, which is how real exposure survives a green-looking pipeline. So
findings are ranked by how likely the flaw is to actually be used:

- **CISA KEV** — the Known Exploited Vulnerabilities catalogue. Membership is
  not a prediction: it means the flaw has been used against real targets.
  Nothing else in the tool outranks it.
- **FIRST EPSS** — a daily-refreshed probability of exploitation in the next
  30 days, giving an ordering where an advisory count gives none.

```
EXPOSED + NO ONE HOME   act on these
pillow  10.0.0  file/media parsing  CVE-2023-4863 on CISA's known-exploited list,
                                    and your pinned version is affected
```

```
Exploitability of your version
  Known exploited (CISA)    CVE-2023-4863
  CVE-2023-4863             >99% chance of exploitation in 30 days
  CVE-2023-50447            1.7% chance of exploitation in 30 days
  CVE-2024-28219            1.0% chance of exploitation in 30 days
    (+12 more scored)
  No EPSS score             1 of 18
    Unscored means unknown, not low risk.
```

Across the test stacks that turns **361 advisories into 11 worth reading first**.

Only advisories affecting your *pinned* version are scored — a CVE fixed five
releases ago is not your problem, and including it would drown the signal.
`pillow 10.4.0` is silent on CVE-2023-4863 for exactly that reason; `10.0.0` is
not.

### What it doesn't claim

EPSS scores the CVE, not your usage: a bug in a code path you never touch scores
the same as one you hit on every request. It ranks, it doesn't decide — which is
why a high score alone never creates a verdict, and why the raw number is always
shown next to the wording. A CVE with no EPSS entry is *unscored*, which is
unknown rather than low risk. And KEV fires rarely on Python libraries — high
precision, low recall — so its silence means nothing on its own.

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

- **never fixed** — advisories whose affected range still includes the
  *latest* release. That is the only reading under which "nobody shipped a
  patch" is a fact: OSV closes ranges with `fixed` or with `last_affected`,
  and GitHub's advisory database encodes most older fixes as the latter. An
  earlier version of this tool only recognised `fixed`, and escalated Django 6
  for a CSRF bug closed at 1.2.7. The strongest signal here, once read right.
- **closed, no fix named** — the range ends before the latest release but no
  fix version is recorded, so there is nothing to put on a timeline. Shown in
  `explain`, and never counted against a package.
- **fixed late** — how often a fix landed only after disclosure, and the median
  size of that window. PyYAML: 2 of 8, median 163 days.
- **fixed timely** — the healthy case, shown so a good project reads as good.

One advisory is one advisory: OSV routinely carries a GHSA record and a PYSEC
record for the same CVE, and they are merged before anything is counted.

### An archived repository is not always an abandoned package

"Repository is archived" is a fact about the URL PyPI declares, and projects
move: Google archived `python-bigquery` when it folded the package into a
monorepo, and `google-cloud-bigquery` ships monthly. So an archived repository
only settles the matter when nothing has been released in the stale window
either. With a recent release it is stated, but as one weak signal, worded
*the code may have moved*.

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

Run inside the project, it reads the pinned version from the lockfile so the
advisories are matched against what you actually install. Anywhere else, pass
it: `package-doctor explain pillow --pin 10.0.0`.

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
| `--stale-push-days N` | tune the weak commit-age signal (default 545) |
| `--max-packages N` | refuse to look up more than this many (default 2000) |
| `--concurrency N` | parallel requests to the free upstream APIs (default 8) |
| `--cache-ttl SECONDS` | how long responses are reused (default 86400) |
| `--no-cache` | bypass the local response cache |

Reads `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pyproject.toml` (PEP 621,
PEP 735 and Poetry), `Pipfile`, `requirements*.txt` and `requirements/*.txt`,
following `-r` includes within the project.

## Data sources

All free, all unauthenticated, no token setup:

- [PyPI JSON API](https://pypi.org/) — release timeline, classifiers, repository URL
- [OSV](https://osv.dev/) — advisories, affected ranges, fixed versions
- [ecosyste.ms](https://ecosyste.ms/) — repository metadata, at 5,000 req/hour
  rather than GitHub's unauthenticated 60
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  vulnerabilities known to be exploited in the wild
- [FIRST EPSS](https://www.first.org/epss/) — exploit probability scores

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

### Growing it

Curating by working down a download list is brute force; most of what you read
does not belong. `research/suggest_map.py` inverts that — it ranks the packages
the map has *no opinion about* by how much that silence costs, and prints what
each one is for so the decision takes seconds:

```bash
package-doctor scan . --json -o scan.json
python research/suggest_map.py --scan scan.json

python research/suggest_map.py --dataset data/pypi-top3000.jsonl --limit 30
```

```
  1. pytorch-lightning
     5 advisories never fixed
     "PyTorch Lightning is the lightweight PyTorch wrapper for ML researchers..."
     https://pypi.org/project/pytorch-lightning/
```

Unfixed advisories rank highest, because if such a package does turn out to sit
at a trust boundary then the map is actively hiding something dangerous.

An advisory count is a reason to look, never the answer. `num2words` reached the
top of that list with three unfixed advisories, and reading them showed a
maintainer account compromise rather than anything the library does with input —
so it belongs in `[reviewed] not_exposed`, with that noted.

## A note on tone

Being listed here is not an accusation. Most unmaintained packages are the work
of volunteers who gave what they could, and "no releases since 2021, repository
archived" is a fact that helps a user without indicting anyone. Findings are
worded that way on purpose. If you find output that reads as a judgement on a
maintainer rather than a description of risk, that is a bug — please report it.

## Contributing

The most useful contribution isn't code — it's arguing with
[`exposure.toml`](src/package_doctor/data/exposure.toml). That file is ~710
judgement calls about which packages sit where an attacker can reach, all made
by one person, and a wrong entry is worse than a missing one.

If you know a corner of Python well — Django, ML, crypto, packaging — twenty
minutes reading the relevant category is worth more than a month of new entries.

```bash
git clone https://github.com/binuka200/package-doctor
cd package-doctor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for what belongs in the map, what
doesn't, and the four principles that are load-bearing enough to have tests
guarding them.

## Tests

```bash
pytest                 # the normal suite: offline, ~0.7s
pytest -m live         # contract tests against the real APIs
```

The default suite serves all HTTP from `httpx.MockTransport`, so no upstream
outage can redden a build. That proves the code is self-consistent but nothing
about upstream, so a second suite runs weekly against real PyPI, OSV,
ecosyste.ms, CISA and FIRST endpoints to catch drift — a renamed field, a
changed envelope, a tightened pagination cap.

Those tests draw one distinction deliberately: **a service being unreachable
skips, a service answering with a shape we do not expect fails.** Somebody
else's outage is not a defect here, and paging on it would train everyone to
ignore the suite; drift silently corrupts findings and is exactly what the
tests are for. There is a test for that distinction itself.

## Accuracy

Measured, not asserted, on sixty open source repositories: web frameworks
and the apps built on them, the pallets and pydantic families, LLM tooling,
ML and data projects, infrastructure and CLI tools, from home-assistant at
1,247 packages down to ansible at 5. The list is
[`research/eval-repos.txt`](research/eval-repos.txt) and the harness is
[`research/evaluate_repos.py`](research/evaluate_repos.py); everything below
reproduces from those two files.

| | |
| --- | --- |
| repositories | 60 (59 with a dependency file the tool reads) |
| packages assessed | 12,973 |
| distinct pinned (package, version) pairs | 6,728 |
| import sites reported | 108,193 |

**Advisory matching, against OSV's own version-scoped query** — the
authoritative answer to "is this pinned version affected?" — over all 6,728
pairs, after collapsing GHSA and PYSEC aliases to their CVE:
**6,727 / 6,728 exact agreement.** The one disagreement is `langsmith 0.3.45`,
whose record carries a range typed `SEMVER` alongside its `ECOSYSTEM` range;
OSV ignores the first for PyPI, this tool reads it, and reports the version
affected. Earlier runs found and fixed three failures, each now a test:
`tornado 6.3.0` matched as a string rather than under PEP 440,
`scrapy 2.17.0` an open-ended range that a matcher waiting for a `fixed`
event never reported, and `click==8.*` stored as a version rather than read
as a range.

**Against `pip-audit`** (`--no-deps -s osv`) on the same pins, compared at the
vulnerability level with identifiers canonicalised to CVE:

| | |
| --- | --- |
| packages flagged, pip-audit / package-doctor | 322 / 322 |
| vulnerabilities found by both | 1,672 |
| found only by pip-audit | **0** |
| found only by package-doctor | 1 (the langsmith range above) |

**Reachability:** of 108,193 import sites reported, 108,162 open to an import
of that package on that line. The 31 remaining are `from _pytest...` and
`import py` attributed to pytest, which is correct — both modules ship in the
pytest distribution — and only the checker's static table did not know it.

The honest limit: both tools read OSV, so this shows we read it correctly, not
that OSV is complete. And it measures the *data* layer.

### The verdicts, read

The verdict layer is a judgement, so the check is reading them. Of the 437
*act on these* verdicts across the sixty projects, 340 rest on the pinned
version being affected by a published advisory, which the OSV agreement above
makes right by construction; they are mostly old lockfiles. The other 97, on
28 distinct packages, rest on maintenance signals, and every one was read:
libraries deprecated by their owners (adal, msrest, oauth2client,
google-generativeai, redis-py-cluster), advisories the maintainers consider
by-design and will not fix (nltk, keras, diskcache), and packages quiet for
three to eight years. Two are arguable at the margin — python-pptx and
requests-kerberos, each just over the two-year threshold — and that is a
threshold choice rather than a misreading.

That result is recent. An earlier version of this tool recognised only a
`fixed` event as closing an advisory's range, and on an eight-project sample
36 of its 64 act verdicts rested on advisories that were in fact closed by
`last_affected`, Django 6 among them for a 2011 CSRF bug. Reading ranges as
OSV does took the sixty-project run from 207 "never fixed" advisory records
to 15.

### The exposure map, measured

The map is the judgement layer, and it is a different kind of claim. Tested
against 3,000 packages, asking whether its call predicts anything real —
whether a package it marks exposed is more likely to have security advisories:

| bucket | packages | have advisories |
| --- | --- | --- |
| curated, exposed | 635 | **31.3%** |
| curated, not exposed | 124 | 12.1% |
| no opinion | 2,236 | 6.8% |

Packages the map calls exposed carry advisories at ~2.6× the rate of packages
it reviewed and cleared, and that holds when controlling for popularity (43.7%
against 16.2% within the top 500). The curated map carries real signal.

**The inference fallback did not.** Packages it guessed as exposed had
advisories at 11.3% — indistinguishable from the 12.1% of packages reviewed and
marked *not* exposed. A hand audit showed why: `Topic :: Security` was catching
bandit, semgrep and pip-audit, which are security *tools*; `Topic :: System ::
Archiving` caught setuptools and wheel; `Framework :: Django` caught
pytest-django and factory-boy. Roughly three in five were wrong.

So inference was cut back to the handful of classifiers that genuinely imply
untrusted input, taking it from 151 packages to 5, and **an inferred category
can no longer produce an actionable verdict** — it can raise something to
*watch* and say why, and that is all. Saying "not reviewed" beats guessing.

### What is still unmeasured

Coverage, on the 12,973 packages above: **45% get a curated call, 55% get no
opinion.** The larger the sample, the longer the tail of transitive
dependencies, and that tail is what "no opinion" is for. Those 55% are not
assessed as safe — they surface as unknown, which is the honest answer, but it
is a gap rather than a result.

And there is no external review. Every batch of repositories scanned so far has
turned up at least one miscategorisation, the rate is falling, and it is not
zero. Treat the advisory numbers as solid and the categories as a draft.

## Use it alongside pip-audit, not instead of it

`pip-audit` is the PyPA tool and is better at what it does: telling you, on every
commit, which pinned versions have known CVEs. Most of what lands in *act on
these* here, it would also find.

What it does not do is tell you which of those to fix first, which of them your
code actually imports, or which of your dependencies has nobody left to ship a
patch at all. That is this tool's job, and it is a different cadence — a
quarterly maintenance review rather than a per-commit gate.

## Background

The reasoning behind this tool is set out in
[Rethinking Dependency Maintenance in the Age of AI Vulnerability Research](https://medium.com/@binukajayaweera/rethinking-dependency-maintenance-in-the-age-of-ai-vulnerability-research-30c8d2f775a6).

## License

MIT
