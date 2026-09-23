# Accuracy

Back to the [README](../README.md).

Measured, not asserted, on a hundred open source repositories: web frameworks
and the apps built on them, the pallets and pydantic families, LLM tooling,
ML and data libraries, security tools, infrastructure and CLI tools, and
applications that ship pinned lockfiles - odoo, awx, warehouse, netbox,
saleor, DefectDojo - from home-assistant at 1,250 packages down to ansible
at 5. The list is [`research/eval-repos.txt`](../research/eval-repos.txt).
[`research/evaluate_repos.py`](../research/evaluate_repos.py) checks the data
layer and [`research/evaluate_verdicts.py`](../research/evaluate_verdicts.py)
checks each verdict against its source; everything below reproduces from those
three files. Last measured on 23 September 2026 with the development version
after 1.0.2 - the fixes the run itself turned up, listed at the end of this
section - against fresh clones.

| | |
| --- | --- |
| repositories | 100 (98 with dependencies the tool can read; letta's repository now holds only documentation, and transformers computes its `install_requires` in `setup.py`, which is parsed, never run) |
| packages assessed | 18,138 |
| distinct pinned (package, version) pairs | 8,261 |
| import sites reported | 116,317 |
| scan time per repository, cold cache | median 22 s, longest 8.5 min (home-assistant) |

**Advisory matching, against OSV's own version-scoped query** — the
authoritative answer to "is this pinned version affected?" — over all 8,261
pairs, after collapsing GHSA and PYSEC aliases to their CVE:
**8,260 / 8,261 exact agreement.** The one disagreement is `langsmith 0.3.45`,
whose record carries a range typed `SEMVER` alongside its `ECOSYSTEM` range;
OSV ignores the first for PyPI, this tool reads it, and reports the version
affected. Earlier runs found and fixed three failures, each now a test:
`tornado 6.3.0` matched as a string rather than under PEP 440,
`scrapy 2.17.0` an open-ended range that a matcher waiting for a `fixed`
event never reported, and `click==8.*` stored as a version rather than read
as a range.

**Against `pip-audit`** (`--no-deps --disable-pip -s osv`) on the same pins,
compared at the vulnerability level with identifiers canonicalised to CVE.
This comparison was last run on the sixty-repository list, on 16 September
2026:

| | |
| --- | --- |
| packages flagged, pip-audit / package-doctor | 327 / 327 |
| vulnerabilities found by both | 1,663 |
| found only by pip-audit | **0** |
| found only by package-doctor | 1 (the langsmith range above) |

Both tools have to read OSV on the same day for this to mean anything. On the
first pass the local cache was six days old, and OSV had attached CVE ids to
three tornado advisories that morning: pip-audit reported them as CVEs, the
cache knew them only by GHSA id, and 22 findings failed to pair up. With the
cache refreshed they matched. A mismatch of this shape is an alias arriving,
not a missed vulnerability.

**Reachability:** of 116,317 import sites reported, 116,283 open to an import
of that package on that line. The 34 remaining are correct and only the
checker's static table did not know it: 33 are `from _pytest...` and
`import py`, which ship in the pytest distribution, and one is
`from packageurl import PackageURL`, which is packageurl-python.

The honest limit: both tools read OSV, so this shows we read it correctly, not
that OSV is complete. And it measures the *data* layer.

**What this run found and fixed**, each now a test:

- *A pre-release named as the fix.* The latest release included alphas,
  betas and nightlies: 13 upgrade verdicts named tornado `6.6a1`, pydantic
  `2.14.0b2` or a yt-dlp dev build as the release to install, and 786
  findings showed a pre-release as the latest. Each stable release also
  cleared the advisories, so no verdict changed - only the advice.
- *Git dependencies looked up on PyPI by name.* A package that `uv.lock` or
  `[tool.uv.sources]` installs from git, and that `pyproject.toml` also lists,
  went to PyPI anyway. zulip's `talon-core` and `zulint` came back "not
  found"; zulip's own `zulip` and `zulip-bots` were judged as the unrelated
  packages of the same name on PyPI.
- *A range naming a pre-release.* celery's `kombu>=5.7.0a1` was reported as
  satisfied by no release, where pip installs `5.7.0a1`.
- *No report when there is nothing to report.* `scan -o` on transformers
  exited 0 without writing the file, failing whatever read it next. The empty
  report now lists the files it could only read in part.

## The verdicts, checked at source

The verdict layer is a judgement, and most of it can still be checked against
the fact it rests on. Across the hundred projects 743 findings ask for work -
14 *exploited*, 175 *replace*, 554 *upgrade*. 584 rest on the pinned version
being affected by a published advisory, which the OSV agreement above makes
right by construction; they are mostly old lockfiles.

**Exploited.** All 14 cite CVEs on CISA's known-exploited list on the day of
the run: starlette in nine projects, litellm in four, pillow in one. The
check was also run the other way, over every pinned version OSV says a KEV
CVE affects, and none escaped the verdict. Nine of the fourteen are imported
by the project's own code.

**Upgrade.** For all 554, OSV confirms the release named as the fix is clear
of every advisory against the pinned version, and none is a pre-release.

**Replace.** The other 159 action verdicts are all *replace*, on 75 distinct
packages, and each rests on a fact rather than a threshold: 143 on an
archived repository, 16 on the maintainer's Inactive classifier. GitHub
confirms 87 of the 88 repositories reported archived; the 88th, iometer's, is
no longer public, so it can be neither confirmed nor refuted. PyPI confirms
all 15 Inactive classifiers. Seven fail the build, because they sit at a
reviewed boundary - adal, bleach, google-generativeai, msrest, msrestazure,
oauth2client and redis-py-cluster, the same seven as the sixty-repository
run. The rest are away from one, where *replace* informs rather than blocks.

The run before 0.9 counted 132 maintenance verdicts, and many sat just past
an age threshold. Age alone now produces *quiet*: all thirteen packages that
run named as threshold cases - requests-toolbelt, olefile, flask-session,
dataclasses-json, jsonpatch, python-pptx, requests-kerberos, requests-ntlm,
pysocks, html5lib, chevron, rfc3339-validator and requests-aws-sign - are
*quiet* in all 108 places they appear here and fail nothing. nltk and keras,
whose unfixed advisories the maintainers consider by design, are
*mitigate*. The full list is in `acts.json` after any run of the harness.

That result is recent. An earlier version of this tool recognised only a
`fixed` event as closing an advisory's range, and on an eight-project sample
36 of its 64 act verdicts rested on advisories that were in fact closed by
`last_affected`, Django 6 among them for a 2011 CSRF bug. Reading ranges as
OSV does took the sixty-project run from 207 "never fixed" advisory records
to 15.

## What a user is asked to do

Right verdicts are not the same as useful ones, so the run also measures what
a project would experience with the default settings.

| | |
| --- | --- |
| packages with an advisory against the pinned version | 617, carrying 2,550 advisories, in 65 repositories |
| findings that fail the build | 507, in 63 repositories: 447 *upgrade*, 46 *replace*, 14 *exploited* |
| per repository that fails | median 3, most 58 (autogen) |
| of those, imported by the project's own code | 170; 12 more only in tests, 325 not imported directly |
| vulnerable but not failing the build | 141: 108 away from a boundary, 33 *mitigate* |

Three readings of that table, the third a limit rather than a result:

- **It is not a noise filter.** 63 of the 65 repositories with a vulnerable
  pin fail at the default level, so as a gate it is nearly as strict as
  pip-audit. The reduction is from 2,550 advisories to a median of three
  findings per project, one per package with the action on it, and exploited
  first.
- **What it adds is the order and the second axis.** Fourteen findings are
  under active exploitation, and 46 findings on 13 packages at a boundary ask
  for a replacement rather than an upgrade: 33 because the project is
  archived, and 13 because an advisory has no fix anywhere and the project
  has gone quiet - diskcache, pdfkit, pypdf2, sqlitedict and sanic-cors. An
  advisory scanner cannot know a project is archived, and reports an unfixable
  advisory with no fix to move to and no reason to look elsewhere.
- **The upgrade it names is the newest release, not the nearest fix.** 161 of
  the build-failing upgrades cross a major version. For 116 a new major is
  what fixes it; for 30 the pinned series already had a fix - paperless-ngx is
  told to move Django 5.2.16 to 6.1.1 when 5.2.17 fixes it - and for 15 OSV
  records no fixed version to compare. Naming the smallest fix is not done
  yet.

Most of what fails the build is not imported by the project directly, and
most of that is transitive. That is deliberate - a transitive parser still
parses the attacker's bytes - but it is the first thing a reviewer will ask
about, and the report says it on every row.

## The exposure map, measured

The map is the judgement layer, and it is a different kind of claim. Tested
against the 3,000 most-downloaded packages (collected 16 September 2026 with
[`research/bulk_scan.py`](../research/bulk_scan.py)), asking whether its call
predicts anything real — whether a package it marks exposed is more likely to
have security advisories.

That test has to exclude part of the map now. Since 0.9.1 many entries were
decided *from* advisories: `suggest_map.py` ranks candidates by what their
advisories cite, and `audit_map.py` checks entries against them. An entry whose
`why` cites an advisory has the outcome built in, and counting it would
measure how the map was built. The fair test is the entries decided from what
the package does:

| bucket | packages | have advisories |
| --- | --- | --- |
| exposed, decided from what it does | 709 | **18.9%** |
| cleared, decided from what it does | 408 | 2.2% |
| cleared as part of a family (typing stubs, generated clients) | 464 | 1.5% |
| no opinion | 1,213 | 1.7% |

Packages the map calls exposed carry advisories at 8.6× the rate of packages it
reviewed and cleared, and that holds when controlling for popularity: 27.9%
against 3.8% within the top 500, 7.2×. The curated map carries real signal.

The ratio is higher than the 2.6× an earlier run reported (635 exposed at 31.3%
against 124 cleared at 12.1%), and not all of that is the map improving. The
cleared set has grown from 124 packages to 408 decided on their own and 464 by
family, and it now includes many small tooling libraries, which rarely draw
advisories at all. *No opinion* sits lower than *cleared* because the packages
with advisories were the first ones decided. The 204 entries left out cite
advisories and carry them at 95%, as they must.

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

The markup classifiers were cut the same way later. Of the unreviewed packages
they guessed as parsing HTML or XML, about one in four did; the rest generate
it (dominate, htmlmin, pytablewriter) or are documentation tooling. A
classifier names the format a package touches, not the direction. The ones
that parse outside markup now have curated entries.

## What is still unmeasured

Coverage, on the 18,138 packages above: **77% get a curated call, 23% get no
opinion** — 39% of packages are marked exposed and 39% reviewed and cleared,
against 75% and 25% on the sixty-repository run. The larger the sample, the
longer the tail of transitive dependencies, and that tail is what "no opinion"
is for. Those 23% are not assessed as safe — they surface as unknown, which is
the honest answer, but it is a gap rather than a result. It has a cost: before
eight entries were added from this run, ten vulnerable packages -
`sqlitedict`, which pickles by default, among them - were not failing any
build only because the map had no opinion of them.

And there is no external review. Every batch of repositories scanned so far has
turned up at least one miscategorisation, the rate is falling, and it is not
zero. Treat the advisory numbers as solid and the categories as a draft.

## How it is tested

```bash
pytest                 # the normal suite: offline, about 4s
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
