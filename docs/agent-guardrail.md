# A guardrail for coding agents

Back to the [README](../README.md).

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
          CVE-2023-4863 on CISA's known-exploited list, and your pinned version is affected; pinned
          version 10.0.0 is affected by 18 advisories: GHSA-3f63-hfp8-52jq, GHSA-44wm-f244-xhp3 and 16
          more; the latest release, 12.3.0, fixes all of them
OK        requests 2.34.2?
          no concerns found
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
comments on them is one the model learns to skim.

A block names the way out, because a refusal an agent cannot act on becomes a
retry of the same command:

```
BLOCK pillow 9.5.0: CVE-2023-4863 on CISA's known-exploited list ...
  -> retry with pillow==12.3.0
```

It reads the shapes an agent actually types, including the ones that install
and execute in a single step - `uv run --with`, `uvx`, `uv tool install`,
`pipx run` and `rye add` - and it says a warning once per session rather than
on every retry. Blocks always repeat: the command was tried again, so it is
answered again.

**Where the install would fetch from.** `--index-url`, `--extra-index-url` and
`--trusted-host` change what a name means, so they are stated: a private index
is noted, and one reached over plain HTTP says that anything on the path can
replace what gets installed. With an index configured, *not on PyPI* stops
being a block and becomes a warning - a package missing from PyPI is what an
internal package looks like, and refusing it is how a team learns to remove
the hook.

**After a resolve.** `uv sync`, `poetry lock` and `pip install -r` name no
package, and what they pull in exists only in the lockfile afterwards. The
same goes for `uv lock`, `poetry install` and `update`, `pdm install`, `lock`
and `update`, `pipenv lock` and `sync`, `pip-compile`, `pip-sync` and
`rye sync`. A
`PostToolUse` hook diffs the lockfile against the last commit and checks what
was added, transitive packages included. It cannot block - the resolve has
happened - so the finding goes to the model as context, with a count of
anything past the first twenty. And when the upstream
services cannot answer, the package is *unchecked* and allowed — a guardrail
that fails closed on somebody else's outage is the first thing a team removes.

## Claude Code hook

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
install nothing are ignored in a millisecond. For `pip install` (and `pip3`
or `python -m pip`), `uv add`, `uv pip install`, `poetry add`, `pipenv install`,
`pdm add`, `pipx install` and `pipx inject`, each package is checked, and:

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

### Edits to dependency files

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
