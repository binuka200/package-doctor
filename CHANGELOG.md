# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- GitHub Actions are pinned to commit SHAs, with Dependabot keeping the pins
  and the Python dependencies current. Added a citation file and README badges.

## [0.1.0] - 2026-09-12

### Added

- Two-axis risk model: a dependency is only escalated when it sits at a trust
  boundary **and** shows evidence that nobody is left to fix it.
- Exposure map of ~710 packages across 14 trust-boundary categories, plus
  reviewed-and-cleared and mature-by-design lists.
- Advisory history from OSV, read as never-fixed / fixed-late / fixed-timely
  rather than a naive time-to-fix.
- Exploitability ranking via CISA KEV and FIRST EPSS, scoped to the pinned
  version — turns "affected by 35 advisories" into which one to read first.
- Reachability: AST-parses your own source and reports where each dependency is
  imported.
- `scan`, `explain` and `cache` commands, JSON output, `--version`, and
  `--fail-on` exit codes for CI.
- Research harness (`research/`) for bulk-scanning PyPI and for deciding what
  the exposure map should cover next.
- `requirements/*.txt` is discovered, and `-r` includes are followed within
  the project, so the pip-tools and Django layouts scan without flags.
- `explain` says when no pinned version was known and advisory matching was
  therefore skipped; the version to match is given with `--pin`.

### Fixed

- Advisory ranges are read with OSV's semantics: `last_affected` closes a
  range inclusively and an `introduced` with no closing event runs to
  infinity. Only `fixed` was recognised before, so an advisory closed by
  `last_affected` read as "no published fix" and an open-ended one never
  matched the pinned version. Across eight real projects that produced 36 of
  64 *act on these* verdicts, all wrong - Django 6 escalated for a CSRF bug
  closed at 1.2.7 - and one missed advisory. "Never fixed" now means the
  latest release is still affected; a range that ends before the latest
  release with no fix named is reported as closed, not counted either way.
- GHSA and PYSEC records of the same CVE are merged before counting.
  cryptography 46.0.7 read as "affected by 7 advisories"; it is four.
- Import sites are named relative to the project directory rather than to
  the package directory being walked, so zulip's `analytics/models.py` and
  `zerver/models.py` no longer both report as `models.py`.
- The project's own package, uv workspace members, and anything a lockfile
  records with a local source are skipped and listed as such, instead of
  being assessed as dependencies. mlflow's report led with mlflow.
- A wildcard such as `click==8.*` is read as a range, not stored as the
  version "8.*", which OSV matched against nothing.
- `requirements/<env>/*.txt` is discovered, one level deep.
- The scan header and the JSON say how many packages had no pinned version
  and so had no advisory matching, instead of implying "no advisories".
- An archived repository with a release inside the stale window is one weak
  signal, worded "the code may have moved", rather than proof of abandonment.
  google-cloud-bigquery's archived repo is a monorepo migration.

### Security

- Terminal output strips control and formatting characters, including whole
  CSI and OSC sequences, from every string that originates outside the
  process: lockfile versions, scanned file names, API-supplied URLs and
  advisory ids. `rich` neutralises markup but passes a raw ESC through, so a
  hostile lockfile could previously wrap a row in a hyperlink to somewhere
  else or clear the screen.
- The source scanner and the dependency-file parsers read only regular files,
  with a bounded read rather than a size check. A FIFO named `evil.py` or a
  symlink to `/dev/zero` in a scanned checkout previously hung the scan.
- Dependency files are capped at 32 MB, and a refused file is reported rather
  than silently treated as empty.
- Pathologically nested TOML and JSON is treated as malformed. `tomllib`
  raises `RecursionError`, not `TOMLDecodeError`, on a lockfile a few thousand
  brackets deep, which previously ended the scan with a traceback.
- CVE identifiers from OSV aliases are validated against their exact form
  before being spliced into the EPSS query string.
- The response cache file is created `0600` before SQLite opens it, rather
  than tightened afterwards.

### Changed

- PyPI responses are reduced to the fields the tool reads before they are
  cached: the release timeline collapses to one upload time and one yanked
  flag per release. The full body was over a megabyte per package on average,
  which put any lockfile past about 230 packages over the cache's size limit
  and into a cycle of pruning fresh entries and refetching them. Reduced
  entries live under a new cache key; old ones expire on their own.

- A response over the size cap is now its own outcome. It was reported as
  "not found on PyPI", which was untrue, and never cached, so every run
  re-downloaded the body just to abandon it. It is now reported as too large
  to read, remembered for the cache lifetime, and the package's advisories
  are still counted from OSV. PyPI's cap is 64 MB, above the 32 MB default,
  because its body is reduced the moment it is parsed; the largest today is
  12.6 MB.

### Measured

On sixty open source repositories (`research/eval-repos.txt`, harness in
`research/evaluate_repos.py`), 12,973 packages:

- Advisory version matching agrees with OSV's own version-scoped query on
  6,727 of 6,728 distinct pinned pairs; the one disagreement is a
  SEMVER-typed range OSV ignores for PyPI and this tool reads.
- Against `pip-audit` on the same pins: 1,672 vulnerabilities found by both,
  **zero missed**, one found additionally (the same range).
- Of 108,193 reported import sites, 108,162 verified against the source line;
  the rest are pytest's `_pytest` and `py` modules, attributed correctly.
- Every act verdict resting on a maintenance signal was read; none was found
  wrong on the tool's stated criteria.
- Exposure map tested for predictive validity across 3,000 packages: packages it
  marks exposed carry advisories at ~2.6x the rate of packages it reviewed and
  cleared.

[Unreleased]: https://github.com/binuka200/package-doctor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/binuka200/package-doctor/releases/tag/v0.1.0
