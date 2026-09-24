# Using package-doctor

Back to the [README](../README.md).

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
  MITIGATE  no fix exists anywhere, but the project is alive
    old-store    1.5.9  deserialization   1 of 1 advisories has no published fix
  UPGRADE   a newer release clears the advisories
    legacy-http  4.0.1  http/network      pinned version 4.0.1 is affected by 3 advisories
                                          the latest release, 4.2.0, fixes all of them

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
it: `package-doctor explain pillow --pin 10.0.0`, or pip's spelling,
`package-doctor explain pillow==10.0.0`. `explain` takes the same
`--src PATH` as `scan`, so both report the same import sites.

## No lockfile?

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

## In CI

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

### GitHub Actions

```yaml
- uses: binuka200/package-doctor@v1.0.0
```

One line scans the checkout, fails the job on what sits at a trust boundary and asks for work,
and writes the report to the job's step summary so nobody opens a log. To
have findings appear as code scanning alerts on the pull request as well:

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: binuka200/package-doctor@v1.0.0
    with:
      upload-sarif: true
      fail-on: boundary     # or exploited, vulnerable, all, never
      args: --direct-only   # anything `scan` takes
```

The action is `package-doctor scan` with `--sarif` and `--markdown`, plus a
response cache carried between runs. Inputs, outputs and defaults are in
[`action.yml`](../action.yml).

### SARIF

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

### pre-commit

```yaml
- repo: https://github.com/binuka200/package-doctor
  rev: v1.0.0
  hooks:
    - id: package-doctor
```

Runs only when a dependency file changes, and the day-long response cache
means the second run of the day is free.

## Accepting a risk

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

`package-doctor check` and the agent hooks read the same file, so a risk
accepted for CI is also allowed when an agent installs it - with the reason
passed to the model (in Gemini CLI, shown to you instead) - and blocks again
once it expires. `check` reports the
acceptance in its JSON as `accepted`.

## Options

| Flag | Meaning |
| --- | --- |
| `--json` | emit JSON instead of the report |
| `-o`, `--output PATH` | write the JSON to a file instead of stdout |
| `--fail-on LEVEL` | exit `1` at this level or worse: `exploited`, `boundary` (default), `vulnerable`, `all`, `never` |
| `--all` | list the groups away from a reviewed trust boundary, instead of a count |
| `--depth N` | how many directories down to look for dependency files when the root declares none (default 2) |
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
