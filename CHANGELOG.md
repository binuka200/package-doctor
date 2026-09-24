# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.4] - 2026-09-24

### Added

- **`package-doctor hook gemini`**, the agent guardrail for Gemini CLI. The
  same install, lockfile and edit checks as the Claude Code hook, in Gemini's
  hook format; see [the guardrail docs](docs/agent-guardrail.md#gemini-cli-hook).
  Before an install, Gemini can pass the model a refusal but not a warning,
  so warnings there reach only the user.
- **`package-doctor hook codex`**, the same guardrail for Codex CLI, with
  warnings reaching the model as they do in Claude Code. After an
  `apply_patch`, every dependency file the patch wrote is checked; see
  [the guardrail docs](docs/agent-guardrail.md#codex-hook).

### Changed

- The hook's decisions are now separate from each agent's hook format
  (`package_doctor.hooks`), so another agent is a parser and a renderer.
  The Claude Code hook's behaviour and output are unchanged, except that an
  edit hook given several files reports them together.

## [1.0.3] - 2026-09-23

### Added

- **`explain` shows when files were last uploaded, not just when the version
  was released.** Wheels for a new Python added to an old release are
  maintainer activity the release date cannot see, and left a tended package
  reading as abandoned. A *Last file upload* row appears when it is later than
  the release date, and the JSON carries `last_upload` for every package.
  Scoring is unchanged. PyPI responses are cached under a new key, so the first
  run after upgrading fetches them again.
- **The JSON report lists dependency files it could only read in part**, as
  `unread`, beside `not_analysed`. A `setup.py` whose `install_requires` is
  computed in Python yields no dependencies, and an empty `findings` from it
  is not a clean project.
- **`research/evaluate_verdicts.py`** checks each verdict's claim at its
  source over an `evaluate_repos.py` run - exploited CVEs against CISA KEV in
  both directions, upgrade targets against OSV, archived repositories against
  GitHub - and measures what fails the build and why. The evaluation list
  grows from 60 repositories to 100.

### Changed

- **Eight packages added to the exposure map**, each one found vulnerable
  and non-blocking in the 100-repository run only because the map had no
  entry: `sqlitedict` (pickles by default), `kerberos`, `sanic-cors`,
  `tensorflow-cpu`, `h2o`, `ragas`, `lmcache` and `couchbase`.

### Fixed

- **`explain` accepts `name==version`.** `package-doctor explain bleach==6.4.0`
  looked up "bleach==6.4.0" as a package name and reported it not found on
  PyPI. The version is now read as the pin, the same as `--pin 6.4.0`; a range
  such as `bleach>=6` is taken as the declared specifier, and a `--pin` that
  disagrees with the name is refused rather than silently picked between.
- **A pre-release is no longer "the latest release".** tornado `6.6a1`,
  pydantic `2.14.0b2` and a yt-dlp nightly were named as the upgrade that
  fixes an advisory, and `check` and the agent hook suggested installing them,
  in 13 findings across 100 repositories; 786 findings showed a pre-release as
  the latest. The latest release now skips pre-releases and dev builds as pip
  does, unless a project has shipped nothing else.
- **A range that names a pre-release admits one.** celery's `kombu>=5.7.0a1`
  was reported as satisfied by no release; pip installs `5.7.0a1`, and the
  assumed version now follows pip's rules exactly.
- **A package a lockfile or `[tool.uv.sources]` installs from git is not
  looked up on PyPI by name.** When `pyproject.toml` also listed it as a plain
  requirement, it went to PyPI anyway: zulip's `talon-core` and `zulint` came
  back "not found", and zulip's own `zulip` and `zulip-bots`, installed from
  git, were judged as the unrelated packages of the same name on PyPI.
  `[tool.uv.sources]` is now read without a lockfile too, and a `path` or
  `workspace` source is the project's own. A `git+` line in one requirements
  file still does not hide the index requirement in another.
- **`scan --json`, `-o`, `--sarif` and `--markdown` write their report when no
  dependencies are found**, instead of exiting 0 with no file, which failed
  the next CI step on a missing path.

## [1.0.2] - 2026-09-16

### Upgrading

If you copied the Claude Code hook configuration from an earlier README, add
`Bash` to the `PostToolUse` matcher so the lockfile check runs after shell
commands:

```json
"PostToolUse": [
  { "matcher": "Bash|Edit|Write|MultiEdit",
    "hooks": [{ "type": "command", "command": "package-doctor hook claude-code", "timeout": 60 }] }
]
```

Without it, only edits to dependency files are checked after the fact.

### Fixed

- **The install hook checks what an install pulls in, not just what it
  names.** `uv add`, `poetry add` and `pipenv install` now trigger the
  lockfile check that previously ran only after resolves such as `uv sync`, so
  a vulnerable or abandoned package two levels down the tree reaches the model
  as context. Names the command typed are left out, since they were checked
  before it ran.
- **The documented hook configuration ran the lockfile check for nobody.** Its
  `PostToolUse` matcher listed only `Edit|Write|MultiEdit`, so the check after
  shell commands never fired. It is now `Bash|Edit|Write|MultiEdit`, in the
  README and the agent guardrail page. The page also stopped claiming coverage
  after pip, pip-tools, PDM and Rye commands, whose lockfiles are not read.
- **`check` and the hook honour accepted risks.** Only `scan` read
  `package-doctor.toml`, although the hook's own block message told the agent
  to ask for an acceptance and rerun. The same rules apply as in `scan`: an
  accepted package is allowed with its reason passed to the model, an expired
  acceptance blocks again and says so, a version-tied one covers only that
  version, and provenance checks are never overridden. `check` gains
  `--config`, and its JSON an `accepted` field.

## [1.0.1] - 2026-09-16

Documentation and metadata. Nothing covered by the 1.0 compatibility promise
changes.

### Changed

- **The README is a landing page.** It went from 1,006 lines to 169: what the
  tool does, the report sections, install, quick start, CI and Claude Code
  setup, and the headline accuracy numbers. The detail moved unchanged into
  `docs/usage.md`, `docs/agent-guardrail.md`, `docs/how-it-works.md`,
  `docs/exposure-map.md` and `docs/accuracy.md`, linked by absolute URL so
  PyPI renders them.
- **The summary says what the tool is for:** which Python dependencies to fix
  first, the ones being exploited and the ones nobody is left to patch. The
  same wording is in the PyPI summary, the GitHub Action description and
  `package-doctor --help`.
- **The accuracy numbers were re-measured on 1.0.0**, on fresh clones: 6,897 of
  6,898 pinned pairs agree with OSV, pip-audit finds nothing package-doctor
  misses, and the exposure map's comparison now excludes entries decided from
  advisories, which would otherwise build the outcome into the test.
- **PyPI keywords** drop `sbom`, which the tool does not do, and add
  `vulnerability`, `osv`, `cisa-kev`, `epss`, `sarif`, `pip-audit` and
  `claude-code`.

### Fixed

- **`--stale-release-days` and `--stale-push-days` have help text**, with their
  defaults, in `scan`, `explain`, `check` and `hook`.
- **The pre-commit hook runs when `setup.py` or `setup.cfg` changes**, both of
  which the scanner reads.
- **Stale documentation**, checked against the code: the Action and pre-commit
  examples pinned v0.3.0; a `check` example showed a warning the tool no longer
  gives; the `scan` example listed its sections out of order; joblib was named
  as a model-loading package; the map size and test time were out of date.
- **Undocumented behaviour is documented:** `research/audit_map.py`, building
  the dataset `suggest_map.py` reads, GitHub as a data source, the `--json`,
  `--output`, `--fail-on`, `--all` and `--depth` options, and every install and
  resolve command the agent guardrail reads.

## [1.0.0] - 2026-09-16

No behaviour changes from 0.9.1. This release marks the interfaces other
tools build on as stable.

### Stable from 1.0

Covered by semantic versioning, so a change that breaks any of these waits
for 2.0:

- the `scan`, `explain`, `check`, `hook` and `cache` commands and their options;
- the `--json` output at `schema_version` 3 - fields may be added, none
  removed or renamed;
- the verdict names *exploited*, *replace*, *mitigate*, *upgrade*, *quiet*,
  *unchecked* and *ok*, and the `--fail-on` levels;
- exit codes: `0` nothing that fails the build, `1` something does, `2` a
  usage error;
- the Claude Code hook's input and output.

**Not frozen: the data.** The exposure map, the advisories, the CISA KEV list
and EPSS scores change continuously, and map updates ship in minor and patch
releases. Upgrading package-doctor can therefore change the verdict on a
package you have not touched - that is the tool getting more accurate, not an
interface change. Pin package-doctor itself when a build must be reproducible.

### Changed

- **The package is marked `Development Status :: 5 - Production/Stable`**,
  replacing *Alpha*.
- **The README shows real output.** Screenshots of `package-doctor scan` and
  `package-doctor explain pillow` on a demo project replace two text blocks,
  one of which still showed the pre-0.9 *EXPLOITED* header. They are served
  from GitHub, so PyPI renders them too.

### Fixed

- **The sdist no longer carries the README screenshots.** `docs/` is excluded,
  keeping the sdist at around 317 KB rather than 1.9 MB.

## [0.9.1] - 2026-09-16

### Added

- **The exposure map is audited against its own advisories.**
  `research/audit_map.py` reads each mapped package's OSV advisories against
  the answer the map gives and reports three disagreements: a package cleared
  as not at a boundary whose advisories cite a trust-boundary weakness, an
  exposed package whose advisories point to a worse consequence than any of
  its categories, and a `why` citing an advisory id OSV has never heard of.
  Naming the advisory in a `why` settles a finding either way, so silence is
  the only thing reported. It runs weekly in the live contract workflow with
  `--strict`; an OSV outage is listed, not failed. A wrong entry is worse than
  a missing one - a missing entry says "boundary not reviewed", a wrong one
  looks exactly like a reviewed answer - and this is the check for it.

### Changed

- **66 map entries the first audit disagreed with were decided from the
  advisory text.** 28 packages gained the category their advisories reached:
  code execution for langchain, llama-index, smolagents, semantic-kernel,
  pillow, chromadb, pdfminer-six, apache-airflow, litellm and open-webui, and
  auth for signature verifiers (ecdsa, rsa, signxml, starkbank-ecdsa) and for
  mcp, fastmcp and mitmproxy. 26 kept their call with the reason recorded -
  mislabelled CWEs such as uvicorn's log injection, opt-in features, trusted or
  local preconditions, and langchain-core, whose serialization flaw stops
  short of code execution. Nine cleared packages now cite the advisories they
  were cleared despite.
- **47 unreviewed packages were decided**, found in a 110-repository random
  sample, most because their own advisories cite a trust-boundary weakness.
  31 are now mapped - among them fugue's pickling RPC server,
  nemo-toolkit and torchgeo's model loaders, lightrag-hku's JWT handling,
  gdown's archive extraction, homeassistant, zeroconf, rpyc and django-ses -
  and 16 are reviewed as not exposed, including vyper, whose advisories are
  miscompiled contracts, and pyngrok, which never sees tunnel traffic.
- **HTML and XML classifiers no longer drive inference.** Of the unreviewed
  packages they guessed as parsing markup, about one in four did; the rest
  generate it (dominate, htmlmin, pytablewriter) or are documentation tooling.
  The five that parse outside markup - inscriptis, mf2py, sickle, onvif-python
  and feedgen - have curated entries instead.

### Fixed

- **Map citations that named no real advisory.** babel cited CVE-2021-20095
  and diskcache GHSA-r8gq-9x9w-jcpg; OSV has neither. They now cite
  CVE-2021-42771 and GHSA-w8v5-vhqr-4h9v. open-webui's reason said it was
  listed under auth, and it never was.

## [0.9.0] - 2026-09-16

### Changed

- **The report is grouped by trust boundary, and the verdicts are named for
  what to do.** Sections used to be a diagnosis to decode ("exposed + no one
  home"), and the boundary was baked into the verdict, so the same work had two
  names depending on whether a human had curated the package yet. Now the group
  carries the priority and the verdict carries the action:

  ```
  FIX TODAY             known exploited, and your version is affected
  AT A TRUST BOUNDARY   replace and upgrade fail the build
  NOT AT A TRUST BOUNDARY   reviewed: worth knowing, not blocking
  BOUNDARY NOT REVIEWED     nobody has judged these yet
  ```

  The verdicts are *exploited*, *replace*, *mitigate*, *upgrade*, *quiet*,
  *unchecked* and *ok*, replacing act/watch/low/unknown. The two lower groups
  print as a count; `--all` lists them.
- **"Quiet for years" no longer asks for a replacement.** Two weak signals are a
  forecast about who would answer, not evidence that anything is wrong, so they
  now produce *quiet*, which never fails a build. Across sixty repositories 19
  of 26 "replace" verdicts rested on age alone with no advisory against the
  version in use. *Replace* now needs proof - an archived repository, the
  maintainer's Inactive classifier, or an unfixable advisory in a project that
  has also gone quiet.
- **An advisory nobody fixed, in a project that is still shipping, is
  *mitigate*.** chromadb, mariadb and nltk were being told to plan a
  replacement while committing daily. Upgrading cannot clear these, so the call
  is a human one and it never fails a build.
- **The trust boundary decides what blocks, not what a finding is called.**
  Exploitation blocks wherever it is found; *replace* and *upgrade* block at a
  reviewed boundary and inform away from one. An inferred exposure is
  unreviewed, so it can never fail a build.
- `--fail-on` takes `exploited`, `boundary` (default), `vulnerable`, `all` or
  `never`. `act`, `watch` and the short-lived `replace`/`upgrade`/`review`/`bump`
  names still work. The action's `fail-on` input follows.
- JSON `schema_version` is 3: findings carry `boundary` ("at", "clear",
  "unreviewed") and `blocks`, and `counts` uses the new verdict names. SARIF
  rules are `package-doctor/exploited`, `/replace`, `/upgrade`, `/mitigate` and
  `/quiet`, and a finding that does not fail the build is downgraded from
  `error` to `warning` so a dashboard shows what a pipeline would.
- **`check` and the Claude Code hook map one-to-one onto the report.** They
  block exactly what a scan fails on - *fix today* anywhere, *replace* or
  *upgrade* at a reviewed trust boundary - and warn on *mitigate*, on the same
  facts away from a boundary, and on a boundary package that has gone quiet.
- **The hook reads the install shapes it was missing.** `uv run --with`,
  `uvx`, `uv tool run`, `uv tool install`, `pipx run` and `rye add` were all
  invisible to it; the first three fetch a package and execute it in one step,
  which is the case the guardrail exists for. `uvx ruff check .` names `ruff`
  and not `check`, and an option value is never read as a package.
- **The hook is aware of where an install would fetch from.** A non-PyPI
  `--index-url` or `--extra-index-url` is stated, and one over plain HTTP - or
  with TLS waived for its host by `--trusted-host` - says so. With a private
  index configured, *not on PyPI* is a warning rather than a block: a package
  missing from PyPI is what an internal package looks like.
- **A block names a requirement that would pass** - `-> retry with
  pillow==12.3.0` - so a refusal is a corrected command rather than a reason
  to try the same one again.
- **A warning is said once per session**, keyed on the event's `session_id`.
  Blocks still repeat every time the command is tried.
- **A `PostToolUse` hook checks what a resolve locked.** `uv sync`,
  `poetry lock` and `pip install -r` type no package name; this diffs the
  lockfile against the last commit and checks what was added, up to twenty
  packages, counting the rest.
- **A healthy package at a trust boundary no longer warns.** Inherited from the
  old watch tier, it fired on seven of the ten packages an agent most often
  adds - `httpx`, `fastapi`, `jinja2` and `requests` among them, each with a
  spotless advisory record - and said nothing anyone could act on.

### Fixed

- **Claude Code hook silently allowed non-`git`/`http(s)` VCS installs.** The
  `PreToolUse` hook's URL/VCS block only recognized four prefixes
  (`http://`, `https://`, `git+`, `ssh://`). `pip install` also accepts
  `hg+`, `bzr+`, `svn+`, and bare `git://` references, including the
  `bzr+lp:name` Launchpad shorthand; none of those matched the allowlist,
  and none parse as a valid PyPI requirement string either, so the hook
  produced no block and no warning at all. `is_remote_install_target()`
  now classifies every scheme pip fetches over the network, and the hook's
  filter uses it instead of the narrower inline tuple.

## [0.8.4] - 2026-09-13

### Fixed

- **Hash-pinned requirements files were read as empty.** `pip-compile
  --generate-hashes` and `uv export` write every requirement as a
  backslash-continued block with one `--hash` per line. The requirements
  parser read the file physically, so no line was a requirement and a
  459-package file scanned as "No dependencies found". Continued lines are
  now joined the way pip does - a trailing backslash continues the logical
  line, a comment ends it - and per-requirement options such as `--hash=...`
  are stripped before the line reaches the requirement parser. `-r` includes
  split across a continuation line are followed as before.

### Measured

The sixty-repository run (`research/eval-repos.txt`) was repeated on 0.8.3,
and the README's Accuracy section now carries these figures:

- 13,042 packages, 6,879 distinct pinned pairs; advisory matching agrees
  with OSV on 6,878 of them, the one disagreement still `langsmith 0.3.45`.
- Against `pip-audit --no-deps --disable-pip -s osv` on the same pins:
  331 packages flagged by each, 1,661 vulnerabilities found by both, zero
  found only by pip-audit, one only by this tool.
- 77,148 import sites, down from 108,193, because 0.8.1 stopped counting
  files under overlapping source roots twice; 77,119 verify, the other 29
  are pytest's `_pytest` and `py` modules.
- 2,257 advisories affecting pinned versions, 27 on CISA KEV or above 10%
  EPSS (13 distinct CVEs).
- Curated coverage 75%, up from 45%, after the 249 map entries in 0.8.3.
- 552 act verdicts, 132 of them on maintenance signals across 42 packages,
  up from 97 on 28; the increase is the larger map, and the README names the
  entrants that sit closest to the release and commit thresholds.
- `letta-ai/letta` no longer has a dependency file in its repository, so 59
  of 60 repositories are read, as before.

## [0.8.3] - 2026-09-13

### Added

- **Families as data.** `[reviewed] families` holds the name patterns the
  map's header used to describe in a comment - `google-cloud-*`, `types-*`,
  `pytest-*`, `opentelemetry-*` and twelve others - each with a reason.
  `is_reviewed` honours them, `explain` shows the family's reason, and the
  suggestion tooling stops proposing their members. An explicit entry beats
  the pattern, which is how `apache-airflow-providers-fab` (auth manager),
  `google-cloud-aiplatform` (stored XSS) and `opentelemetry-instrumentation`
  (request-attribute cardinality DoS) stay exposed inside not-exposed
  families. Exposure map `schema_version` is 6.
- **A reason on every entry.** All 997 category entries, the
  reviewed-and-cleared list and the stable list record what convinced the
  curator; `tests/exposure_unexplained.txt` is empty and stays that way.
- **249 new category entries**, worked from the CWE-backed candidate list
  and the rank 101-1,000 gap: every one of the top 100 and 998 of the top
  1,000 packages by downloads now have a curated call (1,774 of 3,000). New
  shelves with a family test each: inbound webhook verifiers (`stripe`,
  `twilio`, `slack-sdk`, `svix`, `sendgrid`, `django-anymail`), rate
  limiters (`flask-limiter`, `slowapi`, `django-ratelimit`, `limits`),
  broker consumers (`confluent-kafka`, `kafka-python`, `aiokafka`,
  `nats-py`, `faststream`, `arq`, `taskiq`), expression evaluators
  (`simpleeval`, `asteval`, `restrictedpython`, `numexpr`, `sympy`),
  hostile-by-design parsers (`pefile`, `oletools`, `yara-python`,
  `pyelftools`, `lief`, `capstone`), HDF5, netCDF and GDAL readers, notebook
  and app servers (`jupyterlab`, `notebook`, `marimo`, `voila`, `panel`,
  `bokeh`, `nicegui`), the packaging toolchain (`uv`, `poetry`, `pipenv`,
  `installer`), and email parsing.

### Changed

- **Placements.** A package may now carry several categories and the report
  takes the worst consequence: `mlflow`, `vllm`, `sglang`, `bentoml` and
  `ray` add the deserialization, model-loading, framework or remote-access
  categories their advisories describe instead of only llm/agent;
  `pandas` adds deserialization for `read_pickle`; `reportlab` adds
  templating for CVE-2023-33733; `litellm` and `gradio` add web framework.
  Moved: `django-redis` to deserialization (pickle by default),
  `flask-session` to auth, `dateparser`, `lark`, `pyparsing` and `webcolors`
  out of markup into data parsing, `pathvalidate` to archive extraction,
  `lmdb` to file parsing (its advisories are crafted database files),
  `faiss-cpu` to model loading, `docxtpl` to templating, `babel` to
  deserialization (CVE-2021-20095 loaded pickled locale data by
  Accept-Language). `svgwrite`, `xlsxwriter` and `xlwt` write and parse
  nothing and move to reviewed-not-exposed.

### Fixed

- **A package locked at more than one version is scanned at the newest.**
  uv.lock forks a package by Python version or extra, and the first entry
  used to win - which uv lists oldest. GitGuardian/ggshield was scanned as its
  Python 3.9 environment, with act verdicts on `cryptography`, `marshmallow`,
  `requests` and `urllib3` that a 3.10+ install does not have. The older
  versions are now named in a scan note rather than dropped.
- **UTF-16 and BOM-prefixed dependency files are read.** `pip freeze >
  requirements.txt` in PowerShell writes UTF-16; decoded as UTF-8 nothing
  parsed, and microsoft/Table-Pretraining's 31 pins reported as "No
  dependencies found".
- **setup.py is read, and never run.** `install_requires` and
  `extras_require` written as literals - or as a list bound to a name first -
  are taken from the syntax tree. Three of forty randomly sampled
  repositories declared their dependencies nowhere else and scanned as "No
  dependencies found". A list computed in Python is invisible to a parser, so
  the scan names the file as *not fully read* instead of coming back clean.
- **`research/evaluate_repos.py` no longer crashes** on cache rows with no
  response body, which OSV lookups for unknown packages leave behind.
- **A lockfile's version beats a different pin in another file.** The
  newest-wins rule above applied across files too, so a requirements.txt
  newer than the lock would have been scanned instead of what installs.
  the-paperless-project/paperless ships a Pipfile.lock and a requirements.txt
  that disagree on 49 pins, and installs from the lock.
- **A root whose files declare nothing no longer stops discovery.** Mailu's
  root pyproject.toml holds only towncrier settings, so the nested search
  never ran and its pins in core/base/requirements-prod.txt went unscanned:
  "No dependencies found". The same fallback now runs, and says so.

## [0.8.2] - 2026-09-13

### Added

- **Nested discovery.** When the project root has no dependency files,
  `scan` looks up to two directories down - never into tests, docs,
  examples, fixtures, vendored code or hidden directories - and says which
  files it used. A root with files sees no change. `scan .` now works for
  a project whose requirements live in `configs/`.
- **`setup.cfg`.** `install_requires` and `extras_require` are read.
  `setup.py` is deliberately not: a computed `install_requires` is
  invisible to a parser, and a partial answer that looks complete is the
  failure this tool exists to avoid.
- **`explain --src`.** The same repeatable option `scan` has, through the
  same root pruning and merge, so both commands report identical sites.
- Map entries, each with a reason: `flower` (auth; GHSA-q4qm-xhf9-4p8f is
  an OAuth bypass) and `flask-jwt` (auth); `uwsgi` (http); `flask-passlib`
  (crypto); `flask-restplus` and `flask-restx` (web framework). Three new
  families: Flask API frameworks, WSGI and ASGI servers, Celery and its
  tooling.

## [0.8.1] - 2026-09-13

### Fixed

- **Overlapping source roots double-counted import sites.** Auto-detection
  returns each package directory and the project root when it holds a
  script - `core` and `.` for a layout with `core/__init__.py` and
  `app.py` - and a file under both was indexed and reported twice, so
  `explain` listed every site twice and one package claimed 65 sites
  where there were 33. Overlapping `--src` values did the same. Only the
  outermost roots are walked now, and sites from several roots are merged
  by resolved path and line rather than by their rendered string.

## [0.8.0] - 2026-09-13

### Added

- Map entries from a second outside review, each with a reason:
  `flask-httpauth` (CVE-2026-34531 is an authentication bypass) and
  `flask-ipfilter` (auth); `netaddr` (url: before 1.0 it accepted
  inet_aton forms, so `010.0.0.1` parsed as 8.0.0.1 - no CVE, 1.0 simply
  stopped); `flask-expects-json` (data parsing); `flask-mysql` (query);
  `legacycrypt` (crypto); `gearman3` and `python3-gearman` (http - the
  wire protocol is the boundary; nothing is unpickled); and
  `configparser`, `json-log-formatter`, `log-with-context`, `rollbar`,
  `blinker` as reviewed and not exposed. Two new families guard the
  Flask auth extensions and the wire-protocol job queues.

### Changed

- **The commit date is the default branch's, not the repository's push
  time.** GitHub's `pushed_at` advances on a push to any branch or tag and
  read fourteen months newer than the code for `flask-restful`. The last
  commit on the default branch is now read from GitHub's commit feed
  whenever the push time is inside the stale window, and is what the
  staleness signal uses; the push time is kept as the fallback and shown
  in `explain` labelled as such.
- **The watch tier reads as what it is.** Its hint is now *nothing to do
  today: someone is home*, and a clean advisory record is worded
  *healthy record: N of M fixed at or before disclosure* rather than
  presented as the reason for a warning.

### Fixed

- `--src FILE` with a file outside the scanned project rendered import
  sites as `.:LINE`. The path is now given relative to the project, the
  working directory, or in full.
- A `name @ https://…tar.gz` requirement was classified by its suffix as a
  local path named by the whole line. Lines the requirement parser accepts
  are now its to handle; only lines it rejects are classified as git, URL
  or path.
- A bare wheel or sdist URL was named by normalising the whole filename
  (`foo-1-0-py3-none-any-whl`). It is now named by its distribution.
- A renamed repository read as "repository metadata unavailable". GitHub's
  redirect is followed to the new address.
- A failed repository lookup showed only in `explain`. The report table
  and Markdown now carry *missing signal: …* on the row, so a row is not
  mistaken for complete.

## [0.7.0] - 2026-09-13

### Fixed

- **Wildcard pins were analysed as the newest release of all.**
  `certifi==2024.6.*` was recorded as the pin `2024.6.*`, then discarded
  for containing a wildcard, leaving neither a pin nor a range - so the
  newest release of all was analysed and CVE-2024-39689 disappeared from
  the report. A wildcard pin is now kept as the range it is, in every
  parser, and the newest matching release is analysed.
- **setuptools, pip and wheel were dropped without a word.** They were on
  a hardcoded ignore list and never reached the count, the report or the
  JSON. They are analysed like any other package now, and all three are
  in the exposure map with their advisories (CVE-2024-6345, CVE-2025-8869,
  CVE-2022-40898). Only the interpreter itself is still skipped.
- **Dependencies from git, a URL or a local path vanished.** A `git+ssh://`
  line in a requirements file, an `-e` editable, a PEP 508 direct
  reference, a poetry `{ git = ... }` or a git source in a lockfile was
  either skipped silently or looked up on PyPI and reported as "not
  found". They are now recorded and named: the report carries a
  *Not analysed* line, the JSON a `not_analysed` list, and the Markdown a
  note - because a first-party package at a trust boundary is the last
  thing a report should be quiet about.
- `scan` accepts a dependency file as well as a directory, treating the
  file's directory as the project.
- `--src` accepts a single file, as its help text always said.

## [0.6.0] - 2026-09-13

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

[Unreleased]: https://github.com/binuka200/package-doctor/compare/v1.0.4...HEAD
[1.0.4]: https://github.com/binuka200/package-doctor/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/binuka200/package-doctor/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/binuka200/package-doctor/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/binuka200/package-doctor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/binuka200/package-doctor/compare/v0.9.1...v1.0.0
[0.9.1]: https://github.com/binuka200/package-doctor/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/binuka200/package-doctor/compare/v0.8.4...v0.9.0
[0.8.4]: https://github.com/binuka200/package-doctor/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/binuka200/package-doctor/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/binuka200/package-doctor/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/binuka200/package-doctor/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/binuka200/package-doctor/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/binuka200/package-doctor/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/binuka200/package-doctor/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/binuka200/package-doctor/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/binuka200/package-doctor/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/binuka200/package-doctor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/binuka200/package-doctor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/binuka200/package-doctor/releases/tag/v0.1.0
