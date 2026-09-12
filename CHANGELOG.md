# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Measured

- Advisory version matching agrees with OSV's own version-scoped query on 40/40
  real package/version pairs.
- Benchmarked against `pip-audit` over 654 packages: 173 findings in common,
  **zero missed**, three found additionally and verified as real.
- Exposure map tested for predictive validity across 3,000 packages: packages it
  marks exposed carry advisories at ~2.6x the rate of packages it reviewed and
  cleared.

[Unreleased]: https://github.com/binuka200/package-doctor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/binuka200/package-doctor/releases/tag/v0.1.0
