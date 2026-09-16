# package-doctor

[![CI](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/binuka200/package-doctor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![Python](https://img.shields.io/pypi/pyversions/package-doctor.svg)](https://pypi.org/project/package-doctor/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/binuka200/package-doctor/blob/main/LICENSE)

**Tells you which Python dependencies to fix first: the ones being exploited, and the
ones nobody is left to patch. Then stops your coding agent from adding another.**

![package-doctor scan of a ten-dependency project: pillow and litellm under FIX TODAY for CVEs on CISA's known-exploited list; bleach to replace, archived and marked Inactive; nltk to mitigate, with one advisory no release fixes; requests, pyjwt, flask and jinja2 to upgrade; python-dateutil quiet. Seven of ten fail the build.](https://raw.githubusercontent.com/binuka200/package-doctor/main/docs/images/scan.png)

<sub>A demo project with deliberately old pins, scanned on 16 September 2026.
Advisory and exploitation data change daily, so the same pins will not read
the same later.</sub>

In late August 2026, Anthropic's coordinated disclosure programme reported 2,300
vulnerabilities across 392 open source projects. 421 had been patched upstream.
Discovery is becoming automated; remediation still needs a human. So the
question worth asking about a dependency is not *"is it healthy?"* It is:

> **If a vulnerability lands in this package tomorrow, am I exposed, and is
> anyone home to fix it?**

## What it does

- **Two axes, not one.** A package is escalated only when it sits at a trust
  boundary - it parses, decodes or authenticates data an attacker can
  influence - *and* there is proof nobody is left to ship a fix. `mock` going
  quiet is not a finding; an archived auth library is. The boundary call comes
  from a human-reviewed map of about 1,500 packages, each with its reason.
- **Exploited first.** Advisories that affect your pinned version are ranked by
  CISA's known-exploited list and FIRST EPSS, so hundreds of advisories become
  the handful worth reading today.
- **Reachability.** Each finding says whether, and where, your own code imports
  the package.
- **A guardrail for coding agents.** As a Claude Code hook it checks every
  install an agent proposes, and blocks invented names, packages published in
  the last 30 days, and vulnerable or abandoned libraries at a trust boundary -
  with the reason, so the agent picks something else.

Findings are grouped by what to do about them:

| Section | Means | Fails the build by default |
| --- | --- | --- |
| **exploited** | a CVE on CISA's known-exploited list affects your version | yes |
| **replace** | proof nobody is home - archived or marked Inactive - or an unfixable advisory in a project that has gone quiet | at a boundary |
| **upgrade** | advisories affect your version, and a newer release is clear of them | at a boundary |
| **mitigate** | an advisory with no fix anywhere, in a project that is still active | no |
| **quiet** | gone quiet, nothing actually wrong | no |
| **unchecked** | not enough data to judge | no |

## Install

```bash
pip install package-doctor
```

## Quick start

```bash
package-doctor scan                            # everything your project depends on
package-doctor explain pillow                  # the evidence behind one row
package-doctor check requests pillow==10.0.0   # before adding a dependency
```

It reads `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pyproject.toml`, `Pipfile`,
`setup.cfg`, `setup.py` and `requirements*.txt`. Without a lockfile it assumes
the newest release a fresh install would get, and marks that version `?`.

**In CI**, one line scans the checkout, fails the job on what needs work at a
trust boundary, and writes the report to the job summary:

```yaml
- uses: binuka200/package-doctor@v1.0.0
```

It also runs as a pre-commit hook, writes SARIF for code scanning, and lets you
accept a known risk on the record, with a reason and an expiry date.

**As a Claude Code hook**, add this to `.claude/settings.json`:

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

## How accurate is it?

Measured on 60 open source repositories and 13,043 packages, on 16 September
2026:

- **6,897 of 6,898** pinned versions match OSV's own answer about which
  advisories affect them.
- **0 vulnerabilities** that pip-audit found and package-doctor missed, over
  1,663 found by both.
- **78,642 reported import sites** checked against the source line: 78,612
  match outright, and the other 30 are `_pytest` imports, which pytest ships.
- **2,218 advisories** affecting pinned versions, of which **33** are on CISA's
  list or above a 10% exploit probability.

The exposure map carries real signal too: among entries decided from what a
package does, the ones marked exposed have security advisories 8.6× as often as
the ones reviewed and cleared. The
method, and its limits, are in [accuracy](https://github.com/binuka200/package-doctor/blob/main/docs/accuracy.md).

## Use it alongside pip-audit, not instead of it

`pip-audit` is the PyPA tool and is better at what it does: telling you, on every
commit, which pinned versions have known CVEs. Most of what lands in
*fix today*, *upgrade* and *mitigate* here, it would also find.

What it does not do is tell you which of those to fix first, which of them your
code actually imports, or which of your dependencies has nobody left to ship a
patch at all. That is this tool's job, and it is a different cadence — a
quarterly maintenance review rather than a per-commit gate.

## Documentation

- [Using package-doctor](https://github.com/binuka200/package-doctor/blob/main/docs/usage.md) -
  commands, CI, the GitHub Action, SARIF, pre-commit, accepted risks, every option
- [A guardrail for coding agents](https://github.com/binuka200/package-doctor/blob/main/docs/agent-guardrail.md) -
  what `check` and the Claude Code hook block, warn on and allow, and why
- [How package-doctor decides](https://github.com/binuka200/package-doctor/blob/main/docs/how-it-works.md) -
  the two-axis model, exploit ranking, reachability, data sources
- [The exposure map](https://github.com/binuka200/package-doctor/blob/main/docs/exposure-map.md) -
  what counts as a trust boundary, and how the map is grown and audited
- [Accuracy](https://github.com/binuka200/package-doctor/blob/main/docs/accuracy.md) -
  the full measurements, how to reproduce them, and what is still unmeasured
- [Changelog](https://github.com/binuka200/package-doctor/blob/main/CHANGELOG.md)

## Contributing

The most useful contribution isn't code — it's arguing with
[`exposure.toml`](https://github.com/binuka200/package-doctor/blob/main/src/package_doctor/data/exposure.toml),
about 1,500 judgement calls about which packages sit where an attacker can
reach, each with a one-sentence reason. A verdict you think is wrong is worth
the same: post it in
[Discussions](https://github.com/binuka200/package-doctor/discussions/categories/verdicts)
with the output of `package-doctor explain`. See
[CONTRIBUTING.md](https://github.com/binuka200/package-doctor/blob/main/CONTRIBUTING.md)
to get started.

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
