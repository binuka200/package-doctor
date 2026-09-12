# Contributing

Thanks for looking. Most of what this project needs is not code.

## The most useful thing you can do

**Argue with [`exposure.toml`](src/package_doctor/data/exposure.toml).**

That file is ~710 judgement calls about which Python packages sit somewhere an
attacker can reach. Every one of them was made by one person. Some are wrong,
and the wrong ones are worse than the missing ones — a bad entry makes the tool
lie, while a gap only makes it quieter.

If you know a corner of Python well — Django, ML, crypto, async, packaging —
twenty minutes reading the relevant category is worth more than a month of new
entries.

### What belongs in the map

A package belongs in a `[category.*]` list when it:

1. parses, decodes, renders, verifies or transports data that commonly comes
   from outside your trust boundary, **or**
2. makes an authentication or authorisation decision, **or**
3. builds queries or commands from caller-supplied values.

### What does not

- **"It's popular."** Not a criterion. `six` is everywhere and belongs nowhere
  near the map.
- **"It sounds security-related."** `bandit`, `semgrep` and `pip-audit` are
  security *tools*, not trust boundaries. `xxhash` and `mmh3` are not
  cryptographic despite the names.
- **"It has lots of CVEs."** A reason to look, never the answer. `num2words`
  has three advisories with no fix — and reading them shows a maintainer
  account compromise, not anything the library does with input. It is in
  `[reviewed] not_exposed` for exactly that reason.

**Read the advisories before deciding.** Several entries look harmless from
their one-line description and turn out to be textbook: `diskcache` is "a disk
cache" whose advisories say *unsafe pickle deserialization*; `apscheduler` is
"a task scheduler" whose serializers had remote code execution.

### The three lists

| list | meaning |
| --- | --- |
| `[category.*]` | an attacker can reach this |
| `[reviewed] not_exposed` | checked, and they can't — with a note saying why the obvious guess is wrong |
| `[stable] mature` | they can, but the library is finished, so ignore its age |

The second list matters as much as the first. It is how "we checked and it's
fine" stays distinguishable from "nobody has looked", which is a distinction the
rest of the tool is built on.

### Finding something worth deciding

```bash
package-doctor scan . --json -o scan.json
python research/suggest_map.py --scan scan.json
```

That ranks the packages the map has no opinion about by how much the silence
costs, and prints what each one is for. Working the top of that list beats
reading down a popularity ranking.

### Opening the PR

One category change per PR where you can, and say **why** in the description —
ideally quoting the advisory or the API that convinced you. "Adds `foo`" is hard
to review; "adds `foo`, its `load()` unpickles whatever you hand it, see
GHSA-xxxx" takes ten seconds.

## Code

```bash
git clone https://github.com/binuka200/package-doctor
cd package-doctor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                 # offline, ~1s
pytest -m live         # hits the real APIs; opt-in, not run in PR CI
```

The suite is offline by design — HTTP is served by `httpx.MockTransport`, so no
upstream outage can redden a build. CI enforces 85% coverage.

### Principles worth knowing before you change behaviour

These are load-bearing, and there are tests asserting each of them:

- **Missing data is never a bad score.** No advisory history means *unknown*,
  not *healthy*. No repository declared means *unknown*, not *abandoned*. If you
  find code that turns a null into a zero, that's a bug.
- **Release age alone never produces a finding.** It cannot tell an abandoned
  library from a finished one. Two weak signals must agree, or one
  authoritative signal must fire.
- **A guess can never demand action.** An inferred category can raise something
  to *watch*; only a curated one can reach *act on this*.
- **There is no aggregate health score, and there should not be.** A single
  number is the thing users can't act on and maintainers can't argue with.

### Research scripts

`research/` holds the instruments used to study the ecosystem, not the product.
They write to `data/`, which is gitignored. Run `bulk_scan.py` before
`analyse.py` or `suggest_map.py --dataset`.

## Reporting a problem

A finding that reads as a judgement on a maintainer rather than a description of
risk **is a bug** — please report it. Most unmaintained packages are the work of
volunteers who gave what they could, and the tool's wording should reflect that.

For anything security-sensitive, see [SECURITY.md](SECURITY.md).
