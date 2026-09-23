# How package-doctor decides

The reasoning behind every verdict: what counts as a trust boundary, how advisories are ranked, what reachability means, and what the tool deliberately does not claim. Back to the [README](../README.md).

## The two-axis model

Every other scanner in this space scores packages on one axis — how maintained
they look — and then has to explain why it flagged `six`. package-doctor uses two,
and only escalates when both fire.

**Axis 1 — Exposure.** Does this package routinely handle data an attacker can
influence? Authentication, session and token handling, file uploads, archive
extraction, deserialization, HTML parsing, query building, cryptography, URL
parsing, and model loading. This comes from a curated map in
[`exposure.toml`](../src/package_doctor/data/exposure.toml), not from a heuristic.

It holds **1,028 packages across 15 categories**, with 456 more reviewed and
cleared, curated against the 3,000 most-downloaded packages on PyPI — every one
of the top 100 and 998 of the top 1,000 have been reviewed one way or the other, and Django, FastAPI/ML,
document-processing and web-scraping stacks all scan with zero unclassified
packages. Every entry records what convinced the curator, and `explain` shows
it. Anything outside the map falls back to classifier inference, which is
marked `inferred` and flagged with `?` in output so you can distrust it.

**Axis 2 — Remediation capacity.** If a fix were needed, would one ship?

Both must fire. `mock` going quiet is not a finding, because it is not at a
trust boundary. `legacy-auth` going quiet is the whole point.

### Every section is an instruction

Findings are grouped by what to do about them, in order of what it costs to
ignore:

| Section | Means | Fails the build by default |
| --- | --- | --- |
| **exploited** | a CVE on CISA's known-exploited list affects your version | yes |
| **replace** | proof nobody is home - archived or marked Inactive - or an unfixable advisory in a project that has gone quiet | at a boundary |
| **upgrade** | advisories affect your version, and a newer release is clear of them | at a boundary |
| **mitigate** | an advisory with no fix anywhere, in a project that is still active | no |
| **quiet** | gone quiet, nothing actually wrong | no |
| **unchecked** | not enough data to judge | no |

A package at a trust boundary with someone home is *ok*. It is where the next
advisory that matters will land, so `explain` and the JSON still record its
exposure, but there is nothing to do about it today. In a service with many
boundary packages that list is long, and it is information about the service
rather than a queue of work. `--show-ok` lists it.

## Which advisory first

"Affected by 35 advisories" is not a decision. A list that long gets skimmed and
then ignored, which is how real exposure survives a green-looking pipeline. So
findings are ranked by how likely the flaw is to actually be used:

- **CISA KEV** — the Known Exploited Vulnerabilities catalogue. Membership is
  not a prediction: it means the flaw has been used against real targets.
  Nothing else in the tool outranks it.
- **FIRST EPSS** — a daily-refreshed probability of exploitation in the next
  30 days, giving an ordering where an advisory count gives none.

![package-doctor explain pillow: pillow 10.0.0 is FIX TODAY. Exposure is file/media parsing, curated, with code execution as the consequence; imported at app/main.py:5; the repository is active and fixed 75 of 79 advisories before disclosure; 18 advisories affect the pinned version. Under Exploitability, CVE-2023-4863 is on CISA's known-exploited list with a greater than 99% chance of exploitation in 30 days, the next highest is 1.7%, and one advisory has no EPSS score, which means unknown, not low risk.](https://raw.githubusercontent.com/binuka200/package-doctor/main/docs/images/explain-pillow.png)

Across sixty real projects that turns **2,218 advisories affecting pinned
versions into 33 worth reading first** — the ones on CISA's list or above a 10%
exploit probability, in eight packages.

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
EXPLOITED   known exploited, and your version is affected: fix today
pillow  10.0.0  file/media parsing  CVE-2023-4863 on CISA's known-exploited list,
                                    and your pinned version is affected
                                    imported by your code at api/upload.py:2

UPGRADE     a newer release clears the advisories
paramiko 3.5.1  remote access       pinned version 3.5.1 is affected by 1 advisory:
                                    GHSA-r374-rxx8-8654
                                    imported by your code at api/sftp.py:12
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
- an advisory whose affected range **still includes the latest release** —
  nobody has shipped a fix

**Weak** (two must agree before the tool says anything):

- no release in 2 years
- no commits on the default branch in 18 months
- a history of fixing advisories only after public disclosure

The commit date is the default branch's last commit, read from GitHub's
commit feed, not the repository's `pushed_at`. That field advances on a push
to any branch or tag — a Dependabot branch, a rebased pull request — and for
`flask-restful` it read fourteen months newer than the code. It is kept as
the fallback and shown in `explain` as the push date, labelled as such. A
repository that has been renamed is followed to its new address; one whose
metadata cannot be read shows *missing signal* in the report rather than
looking complete.

The release date has the same blind spot from the other side. It is the date
of the newest *version*, so a maintainer who adds wheels for a new Python to
an older release — keeping the package installable without changing its code —
leaves it looking as stale as one nobody has touched. The most recent file
upload across all releases is recorded alongside it, and yanking a release
counts, since that is a maintainer acting too. `explain` shows it as
*Last file upload* only when it is later than the release date, the one case
where the release date alone misleads; the JSON always carries it as
`last_upload`. It is shown, not scored: new wheels say the package is
tended, not that its code is maintained, so the weak release-age signal still
reads the version date.

### On "time to fix"

The obvious metric — days from advisory to patch — is wrong, and the data says
so. Under coordinated disclosure a healthy project ships the patched release at
or *before* the advisory goes public, so the median delta for well-run projects
is zero or negative. Measured across real packages, Django fixed 153 of 161
advisories at or before disclosure, with 7 that cannot be dated; requests,
7 of 8.

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
  size of that window. PyYAML: 1 of 4, median 259 days.
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

## Data sources

All free, all unauthenticated, no token setup:

- [PyPI JSON API](https://pypi.org/) — release timeline, classifiers, repository URL
- [OSV](https://osv.dev/) — advisories, affected ranges, fixed versions
- [ecosyste.ms](https://ecosyste.ms/) — repository metadata, at 5,000 req/hour
  rather than GitHub's unauthenticated 60
- [GitHub](https://github.com/) — each repository's public commit feed, for the
  date of the last commit on the default branch, and its redirect when a
  repository has been renamed; neither uses the REST API or its hourly limit
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  vulnerabilities known to be exploited in the wild
- [FIRST EPSS](https://www.first.org/epss/) — exploit probability scores

Responses are cached in `~/.cache/package-doctor/` for 24 hours. A 429 or a
5xx is retried with backoff, honouring `Retry-After`; if requests still fail,
the report says which host and how many, so a rate-limited run is visibly
degraded rather than quietly incomplete.
