# package-doctor

[![CI](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![Python](https://img.shields.io/pypi/pyversions/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Finds the dependencies that sit at a trust boundary and have no one left to fix them.
Then stops your coding agent from adding another.**

In late August 2026, Anthropic's coordinated disclosure programme reported 2,300
vulnerabilities across 392 open source projects. 421 had been patched upstream.

That ratio is the problem this tool measures. Discovery is becoming automated.
Remediation still needs a human to reproduce the issue, avoid regressions, cut a
release and support everyone downstream. Finding a thousand bugs does not produce
a thousand safe patches.

So the question worth asking about a dependency is not *"is it healthy?"* It is:

> **If a vulnerability lands in this package tomorrow, am I exposed, and is
> anyone home to fix it?**

Two ways to ask it. `package-doctor scan` answers for everything in your
lockfile. `package-doctor check` answers for one package at the moment it is
about to be installed — and as a [Claude Code hook](#a-guardrail-for-coding-agents)
it asks before an agent's `pip install` runs, blocking an invented name, a
package registered last week, or an abandoned library at a trust boundary,
with the reason put in front of the model so it picks something else.

## The two-axis model

Every other scanner in this space scores packages on one axis — how maintained
they look — and then has to explain why it flagged `six`. package-doctor uses two,
and only escalates when both fire.

**Axis 1 — Exposure.** Does this package routinely handle data an attacker can
influence? Authentication, session and token handling, file uploads, archive
extraction, deserialization, HTML parsing, query building, cryptography, URL
parsing, and model loading. This comes from a curated map in
[`exposure.toml`](src/package_doctor/data/exposure.toml), not from a heuristic.

It holds **997 packages across 15 categories**, curated against the 3,000
most-downloaded packages on PyPI — every one of the top 100 and 998 of the top
1,000 have been reviewed one way or the other, and Django, FastAPI/ML,
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

```
EXPLOITED   known exploited, and your version is affected: fix today
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

Across sixty real projects that turns **2,257 advisories affecting pinned
versions into 27 worth reading first** — the ones on CISA's list or above a 10%
exploit probability.

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

## Install

```bash
pip install package-doctor
```

## A guardrail for coding agents

A scan finds problems after they are in the lockfile. A coding agent adds a
dependency in the time it takes to complete an import statement and never
reads the PyPI page, so the useful moment is before `pip install` runs.

```bash
package-doctor check reqeusts pillow==10.0.0 requests six
```

```
BLOCK     reqeusts
          not on PyPI: an install would fail, or fetch whatever someone has registered under this name since
          one edit from requests; did you mean that?
BLOCK     pillow 10.0.0
          CVE-2023-4863 on CISA's known-exploited list, and your pinned version is affected
WARN      requests 2.34.2?
          at a trust boundary (http/network): healthy record: 7 of 8 past advisories fixed at or before disclosure
OK        six 1.17.0?
          reviewed as not at a trust boundary
```

One decision per package: **block**, **warn**, **ok**, or **unchecked**.
Exit `1` on a block (`--fail-on warn` to be stricter), `--json` for tools.

Agents fail in a way people rarely do: they invent names. So three facts can
block on their own, and they are facts rather than inferences: the package
is **not on PyPI**; it was **first published within 30 days** (`--new-days`);
or it is **one edit from a far more common name** and not itself common,
which is the shape of a typo or of a squat. These are about provenance, not
exposure, and they never touch a verdict. Otherwise the scanner's verdict
decides, and it blocks exactly what a scan of the same package would fail on:

| Verdict | At a trust boundary | Anywhere else |
| --- | --- | --- |
| **fix today** | block | block |
| **replace** | block | warn |
| **upgrade** | block | warn |
| **mitigate** | warn | warn |
| **quiet** | warn | silent |
| **unchecked** | allowed, with a note | allowed, with a note |
| **ok** | silent | silent |

A package with nothing to do about it says nothing at all: `httpx`, `fastapi`
and `jinja2` are what an agent should be reaching for, and a guardrail that
comments on them is one the model learns to skim. And when the upstream
services cannot answer, the package is *unchecked* and allowed — a guardrail
that fails closed on somebody else's outage is the first thing a team removes.

### Claude Code hook

Add to `.claude/settings.json` in the project, or `~/.claude/settings.json`
for every project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "package-doctor hook claude-code", "timeout": 60 }
        ]
      }
    ]
  }
}
```

Every shell command the agent proposes passes through the hook. Commands that
install nothing are ignored in a millisecond. For `pip install`, `uv add`,
`poetry add`, `pipenv install`, `pdm add` and `pipx install`, each package is
checked, and:

- a **block** stops the call and puts the reasons in front of the model —
  which is what makes an agent choose a different package instead of retrying
  the same one;
- a **warning** is attached as context for the model, and the call goes
  through your normal permission flow — the hook never grants a permission
  you did not;
- anything else is silent.

If the lookup itself fails, the install is allowed and the model is told it
went unchecked. `--warn-blocks` makes warnings block too. Responses are
cached, so the second check of a package costs nothing.

#### Edits to dependency files

An agent that writes a name into `pyproject.toml` and then runs `uv sync`
never types the name into a shell command, so the install hook cannot see
it. The same command also runs as a PostToolUse hook on edits:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "package-doctor hook claude-code", "timeout": 60 }] }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write|MultiEdit",
        "hooks": [{ "type": "command", "command": "package-doctor hook claude-code", "timeout": 60 }] }
    ]
  }
}
```

After an edit to `pyproject.toml`, `Pipfile` or a `requirements*.txt`, the
hook reads the file and checks only the names the edit introduced: anything
not already in a lockfile or in the version of the file git last committed.
An edit to any other file, or to a lockfile, costs nothing. The edit has
already happened, so this cannot block; the finding goes to the model as
context, with the instruction to remove the package from the file before
anything installs it — which is enough for an agent to fix its own mistake
before a resolver runs.

## Use

```bash
package-doctor scan
```

```
Dependency Risk Report   73 packages · 12 direct
from uv.lock, pyproject.toml

AT A TRUST BOUNDARY   replace and upgrade fail the build
  REPLACE   no one is home: plan a migration
    legacy-auth  2.1.0  auth/session      repository is archived
    old-parser   1.7.4  html/xml parsing  marked Development Status :: 7 - Inactive
  UPGRADE   a newer release clears the advisories
    legacy-http  4.0.1  http/network      pinned version 4.0.1 is affected by 3 advisories
                                          the latest release, 4.2.0, fixes all of them
  MITIGATE  no fix exists anywhere, but the project is alive
    old-store    1.5.9  deserialization   1 of 1 advisories has no published fix

NOT AT A TRUST BOUNDARY   reviewed: worth knowing, not blocking
  9 quiet, 2 upgrade  -  --all to list

BOUNDARY NOT REVIEWED   nobody has judged these yet
  4 quiet  -  --all to list

0 fix today   2 replace   1 mitigate   1 upgrade   13 quiet   0 unchecked   56 ok
4 of these fail the build at the default level
```

Then get the working behind any row:

```bash
package-doctor explain legacy-auth
```

Run inside the project, it reads the pinned version from the lockfile so the
advisories are matched against what you actually install. Anywhere else, pass
it: `package-doctor explain pillow --pin 10.0.0`. `explain` takes the same
`--src PATH` as `scan`, so both report the same import sites.

### No lockfile?

Then nothing says which version you run, and the most probable answer is the
one a fresh `pip install` would pick today: the newest release that satisfies
the declared range, skipping yanked and pre-release versions. package-doctor
assumes that version, and says so everywhere the assumption shows:

```
8 of 8 without a pinned version: advisories matched against the newest release
instead, marked ? (use a lockfile to pin them)

AT A TRUST BOUNDARY   replace and upgrade fail the build
  UPGRADE   a newer release clears the advisories
    old-client  1.3.0?  http/network  newest release 1.3.0 (assumed: nothing pins this package) is affected
```

The `?` is the same mark an inferred exposure carries: something to distrust.
In `explain` the version reads `1.3.0 (assumed)`, an advisory match reads
*newest release 1.3.0 (assumed: nothing pins this package) is affected*, and
the JSON carries `"version_assumed": true`. `--no-assume-latest` turns the
fallback off and skips advisory matching for unpinned packages instead. A
lockfile is still the answer; this is a first run, not a substitute.

Responses are cached for a day. `package-doctor cache path` shows where, and
`package-doctor cache clear` empties it.

### In CI

```bash
package-doctor scan --fail-on boundary
```

Exits `1` on anything under *at a trust boundary* that asks for work - a
replacement or an upgrade - and on active exploitation wherever it is found.
`--fail-on vulnerable` ignores the boundary and fails on every advisory
against a version in use, `--fail-on all` adds *quiet*, `--fail-on exploited`
fails only on what is being exploited, and `--fail-on never` reports only. The
older `act` and `watch` still work.

```bash
package-doctor scan --json -o report.json
package-doctor scan --sarif package-doctor.sarif     # for code scanning
package-doctor scan --markdown "$GITHUB_STEP_SUMMARY" # for the job summary
```

#### GitHub Actions

```yaml
- uses: binuka200/package-doctor@v0.3.0
```

One line scans the checkout, fails the job on what sits at a trust boundary and asks for work,
and writes the report to the job's step summary so nobody opens a log. To
have findings appear as code scanning alerts on the pull request as well:

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: binuka200/package-doctor@v0.3.0
    with:
      upload-sarif: true
      fail-on: boundary     # or exploited, vulnerable, all, never
      args: --direct-only   # anything `scan` takes
```

The action is `package-doctor scan` with `--sarif` and `--markdown`, plus a
response cache carried between runs. Inputs, outputs and defaults are in
[`action.yml`](action.yml).

#### SARIF

`--sarif PATH` writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
report that GitHub code scanning, GitLab and most security dashboards ingest.
Each finding that fails the build is one result at level `error`; the same
verdict away from a reviewed boundary arrives as `warning`, *mitigate* is a
`warning`, and *quiet* is a `note`. Its location
is the first place your own source imports the package, with the other
import sites as related locations; a package your code never imports points
at the line of the dependency file that declared it. *Unchecked* and *ok*
produce nothing, because an alert that
can never be resolved is how a tool gets muted. Accepted risks (below) are
carried as SARIF suppressions, so a dashboard shows them as dismissed with
the reason rather than not at all.

#### pre-commit

```yaml
- repo: https://github.com/binuka200/package-doctor
  rev: v0.3.0
  hooks:
    - id: package-doctor
```

Runs only when a dependency file changes, and the day-long response cache
means the second run of the day is free.

### Accepting a risk

The first true positive with a ticket already filed is where a scanner gets
removed from CI. So a finding can be accepted, on the record, for a while:

```toml
# package-doctor.toml, next to the lockfile
[[accept]]
package = "legacy-auth"
reason = "Replacement lands in Q4, see PROJ-123"
until = 2026-12-31
version = "2.1.0"   # optional: an upgrade brings the finding back for a look
```

Three rules make this safe to offer. Every entry has a **reason**, because
six months on an entry without one cannot be told from a mistake. Every entry
**expires**, because a permanent suppression is how a known exposure survives
every review; when the date passes the build fails again and the row says the
acceptance expired, not that something new appeared. And an accepted finding
**stays in the report**, in a section of its own, out of the exit code and
never out of sight:

```
ACCEPTED RISK   on the record, not failing the build
  legacy-auth  2.1.0  replace  Migration lands in Q4, see PROJ-123
                               until 2026-12-31 (in 3 months)
```

The verdict is not changed by acceptance. It is a fact about the package;
the acceptance is a fact about what you will do. A malformed entry is a
usage error rather than a warning, since an entry that silently failed to
apply would fail a build for no visible reason, and one that silently applied
too widely would hide risk. Entries that match nothing are reported so the
file stays a list of live decisions. The same table can live under
`[tool.package-doctor]` in `pyproject.toml`; `--config PATH` points anywhere
else.

### Options

| Flag | Meaning |
| --- | --- |
| `--direct-only` | skip transitive dependencies |
| `--src PATH` | source directory or file to check for imports (repeatable) |
| `--no-reachability` | skip the import scan of your own source |
| `--show-ok` | also list packages with no concerns |
| `--sarif PATH` | also write a SARIF 2.1.0 report |
| `--markdown PATH` | also write the report as Markdown |
| `--config PATH` | accepted-risk file (default: `package-doctor.toml`) |
| `--no-assume-latest` | with no pin, skip advisory matching rather than assume the newest release |
| `--offline-repo` | skip repository lookups (faster, fewer signals) |
| `--stale-release-days N` | tune the weak release-age signal (default 730) |
| `--stale-push-days N` | tune the weak commit-age signal (default 545) |
| `--max-packages N` | refuse to look up more than this many (default 2000) |
| `--concurrency N` | parallel requests to the free upstream APIs (default 8) |
| `--cache-ttl SECONDS` | how long responses are reused (default 86400) |
| `--no-cache` | bypass the local response cache |

Reads `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pyproject.toml` (PEP 621,
PEP 735 and Poetry), `Pipfile`, `setup.cfg` (`install_requires` and extras), `setup.py` (the
same, when written as literals), `requirements*.txt`, `requirements/*.txt` and one level below that
(`requirements/<env>/*.txt`), following `-r` includes within the project.
`scan PATH` takes a directory or one of those files. When two files pin a
package differently, the lockfile's version is scanned, because that is what
installs; within one lockfile, the newest. The others are named in a note.

Discovery is shallow on purpose: recursing finds vendored fixtures and
example projects, and a report about someone else's test data is noise. When
nothing at the root declares a dependency — no files, or only a
`pyproject.toml` holding tool settings — a bounded fallback looks up to two
directories down, never entering tests, docs, examples, fixtures, vendored
code or hidden directories, and says which files it used. `setup.py` is
parsed, never run: `install_requires` and `extras_require` written as
literals are read, including a list bound to a name first. One computed in
Python — read from a file, chosen by a condition, appended to — is invisible
to a parser, and a partial answer that looks complete is the failure this tool
exists to avoid, so the scan reports the file as *not fully read*.

Dependencies that come from git, a URL or a local path — a `git+ssh://` line,
an `-e` editable, a `name @ url` reference, a git source in a lockfile — are
never looked up, because no registry can speak to them. They are listed under
*Not analysed* rather than dropped: a first-party package at a trust boundary
is the last thing a report should be quiet about.

## Data sources

All free, all unauthenticated, no token setup:

- [PyPI JSON API](https://pypi.org/) — release timeline, classifiers, repository URL
- [OSV](https://osv.dev/) — advisories, affected ranges, fixed versions
- [ecosyste.ms](https://ecosyste.ms/) — repository metadata, at 5,000 req/hour
  rather than GitHub's unauthenticated 60
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  vulnerabilities known to be exploited in the wild
- [FIRST EPSS](https://www.first.org/epss/) — exploit probability scores

Responses are cached in `~/.cache/package-doctor/` for 24 hours. A 429 or a
5xx is retried with backoff, honouring `Retry-After`; if requests still fail,
the report says which host and how many, so a rate-limited run is visibly
degraded rather than quietly incomplete.

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

### Deserialization is not the same as parsing

Two kinds of package turn bytes into data, and a flaw in them costs very
different things. A pickle loader, an unsafe YAML loader, a config system that
instantiates the class a document names: loading is code execution, by
design. A JSON, MessagePack, Avro or date parser: the worst a hostile input
does is exhaust memory or slip past validation. The map keeps them apart —
`deserialization` for the first, `data parsing` for the second — because a
stale `cloudpickle` and a stale `ujson` are not the same finding.

Every category names what a flaw at that boundary tends to cost, from a
fixed vocabulary: *code execution*, *memory corruption*, *file write*,
*account takeover*, *data access*, *script injection*, *request forgery*,
*prompt injection*, *denial of service*. `explain` shows the word, the JSON
carries it as `exposure.consequence`, and within a report section it breaks
ties between findings with the same evidence, worst first. It is a word, not
a number: nothing sums it, weights it, or lets it change a verdict.

### Reviewed-and-safe is not the same as unreviewed

The map carries a third list, `[reviewed] not_exposed`, recording packages a
human checked and decided are *not* at a trust boundary — each with a note
saying why the obvious guess is wrong. Without it, classifier inference fires on
exactly those names. It also means "we looked and it's fine" is distinguishable
in the data from "nobody has looked yet", which is the distinction the rest of
this tool is built on.

Whole shelves are reviewed at once as `[reviewed] families`: `google-cloud-*`,
`types-*`, `pytest-*`, `opentelemetry-*` and a dozen other name patterns
whose members are generated API wrappers, typing stubs or test plugins over a
transport that is already in the map. The pattern is data, so `is_reviewed`
honours it, and an explicit entry always beats it — which is how the one
Airflow provider that is an authentication manager, or the one
`google-cloud-*` package that moves bytes, is recorded as exposed anyway.

### One package, several boundaries

A package can carry more than one category, and the report takes the worst
consequence among them. `mlflow` is llm/agent for what it is and model loading
for what its advisories say went wrong; `pandas` is file parsing for
`read_csv` and deserialization for `read_pickle`; `ray` is a web framework for
its dashboard and remote access for the jobs API that ran arbitrary code. The
alternative — one category per package — forced a choice between what a thing
is for and what breaks, and the second is what a maintainer needs to rank.

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
and tools aimed at web stacks tend not to model it at all. It is also where
advisory data is least conclusive: `torch` and `transformers` each carry
around thirty advisories, and seven or eight per package are closed in OSV
without any fix version named — the unsafe-deserialisation reports their
maintainers regard as by-design. The tool shows those as *closed, no fix
named* and counts them against nothing, so that an ML stack is judged on what
it actually imports, not on a pile of disputed pickle advisories.

PRs welcome — include the reasoning, not just the name.

### A second reader

The map is one person's judgement, which is its stated weakness.
`research/annotate.py` is the instrument for a second one: it draws a blind
sample across the categories, the cleared list and unreviewed packages,
walks a reader through each with the same evidence the curator had, and
reports Cohen's kappa between the two on the distinction that matters —
exposed or not — with every disagreement listed alongside both sides'
reasoning. See [CONTRIBUTING.md](CONTRIBUTING.md#being-the-second-reader).

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
     1 advisory never fixed
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
[`exposure.toml`](src/package_doctor/data/exposure.toml). That file is ~1,440
judgement calls about which packages sit where an attacker can reach, each with
a one-sentence reason, all made by one person, and a wrong entry is worse than
a missing one.

If you know a corner of Python well — Django, ML, crypto, packaging — twenty
minutes reading the relevant category is worth more than a month of new entries.

A verdict you think is wrong is worth the same. Post it in
[Discussions](https://github.com/binuka200/package-doctor/discussions/categories/verdicts)
with the output of `package-doctor explain`; questions go in
[Q&A](https://github.com/binuka200/package-doctor/discussions/categories/q-a).

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
pytest                 # the normal suite: offline, about 2s
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
| packages assessed | 13,042 |
| distinct pinned (package, version) pairs | 6,879 |
| import sites reported | 77,148 |

**Advisory matching, against OSV's own version-scoped query** — the
authoritative answer to "is this pinned version affected?" — over all 6,879
pairs, after collapsing GHSA and PYSEC aliases to their CVE:
**6,878 / 6,879 exact agreement.** The one disagreement is `langsmith 0.3.45`,
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
| packages flagged, pip-audit / package-doctor | 331 / 331 |
| vulnerabilities found by both | 1,661 |
| found only by pip-audit | **0** |
| found only by package-doctor | 1 (the langsmith range above) |

**Reachability:** of 77,148 import sites reported, 77,119 open to an import
of that package on that line. The 29 remaining are `from _pytest...` and
`import py` attributed to pytest, which is correct — both modules ship in the
pytest distribution — and only the checker's static table did not know it.

The honest limit: both tools read OSV, so this shows we read it correctly, not
that OSV is complete. And it measures the *data* layer.

### The verdicts, read

The verdict layer is a judgement, so the check is reading them. This run
predates the split of *act* into *exploited*, *replace* and *upgrade*. Of the 552
*act* verdicts across the sixty projects, 420 rest on the pinned
version being affected by a published advisory, which the OSV agreement above
makes right by construction; they are mostly old lockfiles. The other 132, on
42 distinct packages, rest on maintenance signals, and every one was read:
libraries deprecated or archived by their owners (adal, msrest, msrestazure,
oauth2client, google-generativeai, bleach, redis-py-cluster), advisories the
maintainers consider by-design and will not fix (nltk, keras, diskcache), and
packages quiet for three to eight years (pysocks, html5lib, chevron,
rfc3339-validator, requests-aws-sign). The count rose from 97 on 28 packages
in the previous run because the map grew by 249 entries, and the new entrants
include the ones closest to the thresholds: requests-toolbelt, olefile and
flask-session are a few months past the 18-month commit line, and
dataclasses-json, jsonpatch, python-pptx, requests-kerberos and requests-ntlm
are just over two years without a release. Those are threshold choices rather
than misreadings, but there are more of them than there were, and the list is
in `acts.json` after any run of the harness.

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
can no longer demand a replacement** — it can raise something to *review*
and say why, and that is all. Saying "not reviewed" beats guessing.

### What is still unmeasured

Coverage, on the 13,042 packages above: **75% get a curated call, 25% get no
opinion** — 37% of packages are marked exposed and 38% reviewed and cleared,
up from 45% curated in the previous run after 249 map entries were added. The larger the sample, the longer the tail of transitive
dependencies, and that tail is what "no opinion" is for. Those 25% are not
assessed as safe — they surface as unknown, which is the honest answer, but it
is a gap rather than a result.

And there is no external review. Every batch of repositories scanned so far has
turned up at least one miscategorisation, the rate is falling, and it is not
zero. Treat the advisory numbers as solid and the categories as a draft.

## Use it alongside pip-audit, not instead of it

`pip-audit` is the PyPA tool and is better at what it does: telling you, on every
commit, which pinned versions have known CVEs. Most of what lands in
*fix today*, *upgrade* and *mitigate* here, it would also find.

What it does not do is tell you which of those to fix first, which of them your
code actually imports, or which of your dependencies has nobody left to ship a
patch at all. That is this tool's job, and it is a different cadence — a
quarterly maintenance review rather than a per-commit gate.

## Background

The reasoning behind this tool is set out in
[Rethinking Dependency Maintenance in the Age of AI Vulnerability Research](https://medium.com/@binukajayaweera/rethinking-dependency-maintenance-in-the-age-of-ai-vulnerability-research-30c8d2f775a6).

## License

MIT
