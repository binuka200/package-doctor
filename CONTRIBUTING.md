# Contributing

Thanks for looking. Most of what this project needs is not code.

## The most useful thing you can do

**Argue with [`exposure.toml`](src/package_doctor/data/exposure.toml).**

That file is about 1,500 judgement calls about which Python packages sit somewhere an
attacker can reach, each with a one-sentence reason. Every one of them was made
by one person. Some are wrong,
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

**Deserialization means pickle-class.** A package goes in `deserialization`
when its loader can instantiate arbitrary objects or run code: pickle and
everything built on it, unsafe YAML loaders, config that names classes. A
JSON, MessagePack, Avro or date parser goes in `parsing`, where a hostile
input costs denial of service rather than code execution. Each category
names its consequence from the vocabulary in `exposure.py`; a new category
must pick one.

**Read the advisories before deciding.** Several entries look harmless from
their one-line description and turn out to be textbook: `diskcache` is "a disk
cache" whose advisories say *unsafe pickle deserialization*; `apscheduler` is
"a task scheduler" whose serializers had remote code execution.

### The four lists

| list | meaning |
| --- | --- |
| `[category.*]` | an attacker can reach this — and a package may sit in more than one |
| `[reviewed] not_exposed` | checked, and they can't — with a note saying why the obvious guess is wrong |
| `[reviewed] families` | a whole shelf checked at once by name pattern — `types-*`, `google-cloud-*` — with an explicit entry anywhere else overriding it |
| `[stable] mature` | they can, but the library is finished, so ignore its age |

The second list matters as much as the first. It is how "we checked and it's
fine" stays distinguishable from "nobody has looked", which is a distinction the
rest of the tool is built on.

### Being the second reader

Every entry was made by one person. The most valuable review is a second
one made blind, with the same evidence, and a number for how often the two
agree:

```bash
python research/annotate.py sample --out research/annotations/sample.json \
    --dataset data/pypi-top3000.jsonl        # optional: adds unreviewed packages
python research/annotate.py run research/annotations/sample.json --annotator you
python research/annotate.py agree research/annotations/sample.json research/annotations/you.jsonl
```

The sample is drawn across the categories, the cleared list and packages
the map has no opinion about, and does not contain the curator's answers.
The session shows each package's summary, topics and advisories with their
CWE ids, and asks for a category or `n`. A note after your answer is the
part that matters most: it becomes the `why` of an entry.

`agree` reports Cohen's kappa for exposed-or-not, which is the distinction
the verdict turns on, and lists every disagreement with both sides'
reasoning. Each disagreement is either a wrong entry or a criterion that
was never written down; either is worth a PR. Your calls on packages the
map had no opinion about are printed as entries ready to paste.

### Families

`tests/test_map_families.py` lists packages that do the same job at the
same boundary - SQL drivers, task queues, git libraries, test doubles - and
fails when one member is decided differently from its siblings. When you
add a package that has obvious siblings, add the family: it is the cheapest
way to make sure the next one gets decided too.

### Finding something worth deciding

```bash
package-doctor scan . --json -o scan.json
python research/suggest_map.py --scan scan.json
```

That ranks the packages the map has no opinion about by what their
advisories say went wrong — a deserialization or injection CWE argues for a
category far better than an advisory count does — then by how much the
silence costs, and prints what each one is for. Working the top of that list
beats reading down a popularity ranking.

### Writing the entry

Use the table form and put the reason in the data, not just the PR:

```toml
{ name = "foo", why = "load() unpickles whatever you hand it, see GHSA-xxxx" },
```

`package-doctor explain foo` shows that sentence, and it is what the next
reviewer argues with. CI fails on a new category entry without a `why`. Every entry now has one;
`tests/exposure_unexplained.txt` is the empty list that used to hold the
exceptions, kept so the test that enforces this stays in place.

### Opening the PR

One category change per PR where you can. With the reason in the entry, the
description only needs to say what you read to reach it.

## Code

```bash
git clone https://github.com/binuka200/package-doctor
cd package-doctor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                 # offline, about 4s
pytest -m live         # hits the real APIs; opt-in, not run in PR CI
ruff check src tests research
```

The suite is offline by design — HTTP is served by `httpx.MockTransport`, so no
upstream outage can redden a build. CI enforces 85% coverage and a clean
`ruff check`; the rule set is in `pyproject.toml` and is deliberately small.

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

`evaluate_repos.py` produces the accuracy figures in the README: it clones the
repositories listed in `eval-repos.txt`, scans them, checks every pinned
package against OSV's own version query and every import site against the
source line, and dumps the verdicts that ask for work (*exploited*, *replace*,
*upgrade*) for reading. Re-run it after any
change to advisory matching or the risk rules, and update the README if the
numbers move.

`audit_map.py` checks the map against the advisories it was curated from: a
package cleared as not exposed whose advisories cite a boundary weakness, an
exposed package whose advisories reached a worse consequence than its
categories, and a `why` citing an advisory id that does not exist. Run it
after editing `exposure.toml`; the weekly live-contracts job runs it with
`--strict`. A finding is settled by naming the advisory in the `why` of the
entry that acts on it, or of the entry that declines to and says why.

## Reporting a problem

A finding that reads as a judgement on a maintainer rather than a description of
risk **is a bug** — please report it. Most unmaintained packages are the work of
volunteers who gave what they could, and the tool's wording should reflect that.

For anything security-sensitive, see [SECURITY.md](SECURITY.md).
