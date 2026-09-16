# Accuracy

Back to the [README](../README.md).

Measured, not asserted, on sixty open source repositories: web frameworks
and the apps built on them, the pallets and pydantic families, LLM tooling,
ML and data projects, infrastructure and CLI tools, from home-assistant at
1,250 packages down to ansible at 5. The list is
[`research/eval-repos.txt`](../research/eval-repos.txt) and the harness is
[`research/evaluate_repos.py`](../research/evaluate_repos.py); everything below
reproduces from those two files. Last measured on 16 September 2026 with
package-doctor 1.0.0, against fresh clones.

| | |
| --- | --- |
| repositories | 60 (59 with a dependency file the tool reads; letta's repository now holds only documentation) |
| packages assessed | 13,043 |
| distinct pinned (package, version) pairs | 6,898 |
| import sites reported | 78,642 |

**Advisory matching, against OSV's own version-scoped query** — the
authoritative answer to "is this pinned version affected?" — over all 6,898
pairs, after collapsing GHSA and PYSEC aliases to their CVE:
**6,897 / 6,898 exact agreement.** The one disagreement is `langsmith 0.3.45`,
whose record carries a range typed `SEMVER` alongside its `ECOSYSTEM` range;
OSV ignores the first for PyPI, this tool reads it, and reports the version
affected. Earlier runs found and fixed three failures, each now a test:
`tornado 6.3.0` matched as a string rather than under PEP 440,
`scrapy 2.17.0` an open-ended range that a matcher waiting for a `fixed`
event never reported, and `click==8.*` stored as a version rather than read
as a range.

**Against `pip-audit`** (`--no-deps --disable-pip -s osv`) on the same pins,
compared at the vulnerability level with identifiers canonicalised to CVE:

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

**Reachability:** of 78,642 import sites reported, 78,612 open to an import
of that package on that line. The 30 remaining are `from _pytest...` and
`import py` attributed to pytest, which is correct — both modules ship in the
pytest distribution — and only the checker's static table did not know it.

The honest limit: both tools read OSV, so this shows we read it correctly, not
that OSV is complete. And it measures the *data* layer.

## The verdicts, read

The verdict layer is a judgement, so the check is reading them. Across the
sixty projects 566 findings ask for work - 14 *exploited*, 111 *replace*, 441
*upgrade*. 468 rest on the pinned version being affected by a published
advisory, which the OSV agreement above makes right by construction; they are
mostly old lockfiles.

The other 98 are all *replace*, on 58 distinct packages, and each rests on a
fact rather than a threshold: 91 on an archived repository, 7 on the
maintainer's Inactive classifier. Every such claim in the run was checked at
source. GitHub confirms 74 of the 75 repositories reported archived; the 75th,
iometer's, is no longer public, so it can be neither confirmed nor refuted,
and its verdict is *quiet* in any case. PyPI confirms all 11 Inactive
classifiers. Seven of the 58 fail the build, because they sit at a reviewed
boundary: adal, bleach, google-generativeai, msrest, msrestazure, oauth2client
and redis-py-cluster, libraries their owners deprecated or archived. The rest
are away from one, where *replace* informs rather than blocks.

The previous run, before 0.9, counted 132 maintenance verdicts, and many sat
just past an age threshold. Age alone now produces *quiet*: all thirteen
packages that run named as threshold cases - requests-toolbelt, olefile,
flask-session, dataclasses-json, jsonpatch, python-pptx, requests-kerberos,
requests-ntlm, pysocks, html5lib, chevron, rfc3339-validator and
requests-aws-sign - are *quiet* here and fail nothing. nltk and keras, whose
unfixed advisories the maintainers consider by design, are *mitigate*. The
full list is in `acts.json` after any run of the harness.

That result is recent. An earlier version of this tool recognised only a
`fixed` event as closing an advisory's range, and on an eight-project sample
36 of its 64 act verdicts rested on advisories that were in fact closed by
`last_affected`, Django 6 among them for a 2011 CSRF bug. Reading ranges as
OSV does took the sixty-project run from 207 "never fixed" advisory records
to 15.

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

Coverage, on the 13,043 packages above: **75% get a curated call, 25% get no
opinion** — 37% of packages are marked exposed and 38% reviewed and cleared,
unchanged from the previous run. The larger the sample, the longer the tail of transitive
dependencies, and that tail is what "no opinion" is for. Those 25% are not
assessed as safe — they surface as unknown, which is the honest answer, but it
is a gap rather than a result.

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
