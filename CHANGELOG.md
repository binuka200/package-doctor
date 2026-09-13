# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The Claude Code hook also runs on edits.** Registered as a PostToolUse
  hook on Edit, Write and MultiEdit, `package-doctor hook claude-code`
  reads an edited `pyproject.toml`, `Pipfile` or `requirements*.txt` and
  checks only the names the edit introduced - those in neither a lockfile
  nor the committed version of the file. An edit cannot be blocked after
  the fact, so findings reach the model as context with the instruction
  to remove the package before anything installs it. Edits to other files
  and to lockfiles cost nothing.

## [0.5.0] - 2026-09-13

### Added

- **`check`: a guardrail for the moment a dependency is added.**
  `package-doctor check NAME[==VERSION]...` prints one decision per
  package - block, warn, ok or unchecked - with the reasons, and exits `1`
  on a block. Three provenance facts can block on their own: not on PyPI,
  first published within `--new-days` (default 30), or one edit from a
  far more common name. The scanner's verdict does the rest: *act* blocks,
  *watch* warns. A failed lookup is *unchecked* and allowed.
- **A Claude Code hook.** `package-doctor hook claude-code` reads a
  PreToolUse event, finds what the shell command would install (pip, uv,
  poetry, pipenv, pdm, pipx, `python -m pip`, chained commands), and blocks
  with the reasons shown to the model, warns as context without granting
  any permission, or stays silent. It fails open.
- `first_release` on each finding, and a shipped list of the 1,500
  most-downloaded package names for the near-miss check.

## [0.4.0] - 2026-09-13

### Added

- **Evidence per map entry.** An exposure map entry can be a table
  `{ name = "...", why = "..." }` recording what convinced the curator.
  `explain` shows it under *Why* and the JSON carries it as `exposure.why`.
  Every reviewed-and-cleared entry now records its reason as data rather
  than as a comment. Category entries without one are frozen in
  `tests/exposure_unexplained.txt`, which only shrinks; CI fails on a new
  category entry that does not say why.
- **CWE-guided map suggestions.** `research/suggest_map.py` reads the CWE
  ids on each unreviewed package's advisories and ranks packages whose
  advisories cite a trust-boundary weakness (deserialization, injection,
  traversal, authentication, certificate validation) above ones that are
  merely unfixed or archived, with the category the advisories argue for.
  The mapping lives in `package_doctor.cwe`; `bulk_scan.py` records the
  ids so a dataset carries them.

- **A second-reader instrument.** `research/annotate.py` draws a blind,
  stratified sample of the map, runs an annotation session with each
  package's summary, topics and advisories, and reports Cohen's kappa
  against the map for exposed-or-not and for category, listing every
  disagreement with both sides' reasoning and printing calls on
  unreviewed packages as entries to paste.
- **Family consistency.** `tests/test_map_families.py` lists packages that
  do the same job at the same boundary and fails when one member is
  decided differently from its siblings.
- Map entries, each with a reason: `pyodbc`, `cx-oracle`, `oracledb`
  (query); `azure-storage-blob`, `dnspython`, `pycares`, `aiodns`,
  `python-socketio`, `python-engineio` (http); `gcsfs`, `adlfs` (url);
  `sentencepiece` (model loading); `celery`, `rq`, `dramatiq`, `huey`
  (deserialization); `napalm`, `dulwich`, `pygit2` (remote access);
  `dynaconf` (templating); and `typer`, `docopt`, `fire`, `sphinx`, `pdoc`,
  `moto`, `responses`, `pydantic-settings`, `environs` as reviewed and not
  exposed.

- **A consequence for every category.** Each category names what a flaw at
  that boundary tends to cost, from a fixed vocabulary (code execution,
  memory corruption, file write, account takeover, data access, script
  injection, request forgery, prompt injection, denial of service).
  `explain` shows it, JSON and SARIF carry it as `consequence`, and within
  a report section it breaks ties between findings with the same evidence,
  worst first. It is categorical and never changes a verdict.

### Changed

- **Deserialization is split.** `deserialization` now holds only the 29
  packages whose loaders can instantiate arbitrary objects or run code -
  pickle and its descendants, unsafe YAML loaders, config that names
  classes, and the queues and caches that pickle their payloads. The other
  57 - JSON, MessagePack, Avro, Protobuf, schema validators, date and
  encoding parsers - move to a new `data parsing` category whose
  consequence is denial of service. A stale `cloudpickle` and a stale
  `ujson` no longer read as the same finding.
- Exposure map `schema_version` is 5.
- `gitpython` moves from reviewed-and-cleared to *remote access*. Its
  advisories are command injection through git options and an untrusted
  search path; anything that clones a repository it was handed is at a
  boundary. The old entry was wrong.

## [0.3.0] - 2026-09-13

### Added

- **Accepted risks.** A `package-doctor.toml` next to the lockfile (or a
  `[tool.package-doctor]` table in `pyproject.toml`) lists findings the team
  has decided to carry, each with a reason and an expiry date, optionally
  bound to a version. An accepted finding stops failing the build and moves
  to its own section of the report; it is never hidden. When the date
  passes, the build fails again and the row says the acceptance expired.
  A malformed entry is a usage error, not a warning. `--config PATH` points
  at a different file.
- **Unpinned packages are matched against the newest release.** With no
  lockfile, the version a fresh `pip install` would resolve to - highest
  non-yanked, non-pre-release version satisfying the declared range - stands
  in for the pin. It is marked `?` in the table, called an assumption in
  every claim built on it, and carried as `version_assumed` in JSON.
  `--no-assume-latest` restores the old behaviour of skipping advisory
  matching.
- **SARIF output.** `scan --sarif PATH` writes a SARIF 2.1.0 report: one
  result per *act*, *watch* or *low* finding, located at the first import
  site in the project's own source (or the line of the dependency file that
  declared it), with an accepted risk carried as a SARIF suppression so a
  dashboard shows it as dismissed with the reason.
- **Markdown output.** `scan --markdown PATH` writes the report as
  GitHub-flavoured Markdown, for a job's step summary.
- **A GitHub Action.** `uses: binuka200/package-doctor@v0.3.0` scans the
  checkout, fails on *act* findings, writes the step summary, and can upload
  SARIF to code scanning. Responses are cached between runs.
- **A pre-commit hook.** Runs the scan when a dependency file changes.

### Changed

- JSON `schema_version` is now 2: findings carry `version_assumed`,
  `specifier` and `accepted`; the top level carries `accepted` and `assumed`
  counts. Everything from version 1 is still present with the same meaning.
- The `--fail-on` exit code ignores findings covered by an unexpired
  acceptance. Verdicts themselves are unchanged by acceptance.

## [0.2.0] - 2026-09-13

### Added

- Requests to the upstream APIs are retried on a 429, a 5xx or a transport
  error: three attempts with exponential backoff and jitter, honouring
  `Retry-After` up to a cap. A single rate-limit response used to become a
  silent gap for that package.
- A scan that still lost requests after retrying says so: a yellow line
  under the report names the host and the count, and the JSON carries a
  `degraded` map, so a degraded run is visibly degraded rather than clean.
- CI runs on macOS and Windows as well as Linux, on the oldest and newest
  supported Pythons.

### Changed

- GitHub Actions are pinned to commit SHAs, with Dependabot keeping the pins
  and the Python dependencies current. Added a citation file and README badges.
- README examples and figures updated to the current advisory semantics; the
  research bulk scan now uses the product's definition of "never fixed".

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

[Unreleased]: https://github.com/binuka200/package-doctor/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/binuka200/package-doctor/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/binuka200/package-doctor/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/binuka200/package-doctor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/binuka200/package-doctor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/binuka200/package-doctor/releases/tag/v0.1.0
