# The exposure map

Back to the [README](../README.md).

[`exposure.toml`](../src/package_doctor/data/exposure.toml) is the part of this tool
that cannot be scraped, and it is deliberately a plain data file so it can be
argued with. A package belongs in it when it:

1. parses, decodes, renders, verifies or transports data that commonly
   originates outside the trust boundary, **or**
2. makes an authentication or authorisation decision, **or**
3. constructs queries or commands from caller-supplied values.

"Popular" is not a criterion. Neither is "sounds security-adjacent" — `xxhash`
and `mmh3` are deliberately **not** in the crypto category, because they are not
cryptographic, and `tiktoken` tokenises text rather than issuing auth tokens.

## Deserialization is not the same as parsing

Two kinds of package turn bytes into data, and a flaw in them costs very
different things. A pickle loader, an unsafe YAML loader, a config system that
instantiates the class a document names: loading is code execution, by
design. A JSON, MessagePack, Avro or date parser: the worst a hostile input
does is exhaust memory or slip past validation. The map keeps them apart —
`deserialization` for the first, `data parsing` for the second — because a
stale `cloudpickle` and a stale `ujson` are not the same finding.

Every category names what a flaw at that boundary tends to cost, from a
fixed vocabulary: *code execution*, *memory corruption*, *file write*,
*account takeover*, *data access*, *script injection*, *request forgery*,
*prompt injection*, *denial of service*. `explain` shows the word, the JSON
carries it as `exposure.consequence`, and within a report section it breaks
ties between findings with the same evidence, worst first. It is a word, not
a number: nothing sums it, weights it, or lets it change a verdict.

## Reviewed-and-safe is not the same as unreviewed

The map carries a third list, `[reviewed] not_exposed`, recording packages a
human checked and decided are *not* at a trust boundary — each with a note
saying why the obvious guess is wrong. Without it, classifier inference fires on
exactly those names. It also means "we looked and it's fine" is distinguishable
in the data from "nobody has looked yet", which is the distinction the rest of
this tool is built on.

Whole shelves are reviewed at once as `[reviewed] families`: `google-cloud-*`,
`types-*`, `pytest-*`, `opentelemetry-*` and a dozen other name patterns
whose members are generated API wrappers, typing stubs or test plugins over a
transport that is already in the map. The pattern is data, so `is_reviewed`
honours it, and an explicit entry always beats it — which is how the one
Airflow provider that is an authentication manager, or the one
`google-cloud-*` package that moves bytes, is recorded as exposed anyway.

## One package, several boundaries

A package can carry more than one category, and the report takes the worst
consequence among them. `mlflow` is llm/agent for what it is and model loading
for what its advisories say went wrong; `pandas` is file parsing for
`read_csv` and deserialization for `read_pickle`; `ray` is a web framework for
its dashboard and remote access for the jobs API that ran arbitrary code. The
alternative — one category per package — forced a choice between what a thing
is for and what breaks, and the second is what a maintainer needs to rank.

## Depth is not the same as breadth

Beyond the top few hundred, most packages genuinely belong in neither list: a
plotting library or a CLI helper needs no entry, and adding one would be noise.
So raw "percent of PyPI covered" is the wrong measure. The one that matters is
whether a real lockfile scans without gaps — which is why the map is curated
against download-ranked data and checked against whole stacks rather than grown
for its own sake.

## One boundary most scanners miss

`[category.ml_model]` covers `torch`, `transformers`, `huggingface-hub`,
`keras` and friends. Loading pickle-based weights is arbitrary code execution,
and tools aimed at web stacks tend not to model it at all. It is also where
advisory data is least conclusive: `torch` and `transformers` each carry
around thirty advisories, and seven or eight per package are closed in OSV
without any fix version named — the unsafe-deserialisation reports their
maintainers regard as by-design. The tool shows those as *closed, no fix
named* and counts them against nothing, so that an ML stack is judged on what
it actually imports, not on a pile of disputed pickle advisories.

PRs welcome — include the reasoning, not just the name.

## A second reader

The map is one person's judgement, which is its stated weakness.
`research/annotate.py` is the instrument for a second one: it draws a blind
sample across the categories, the cleared list and unreviewed packages,
walks a reader through each with the same evidence the curator had, and
reports Cohen's kappa between the two on the distinction that matters —
exposed or not — with every disagreement listed alongside both sides'
reasoning. See [CONTRIBUTING.md](../CONTRIBUTING.md#being-the-second-reader).

## Growing it

Curating by working down a download list is brute force; most of what you read
does not belong. `research/suggest_map.py` inverts that — it ranks the packages
the map has *no opinion about* by how much that silence costs, and prints what
each one is for so the decision takes seconds:

```bash
package-doctor scan . --json -o scan.json
python research/suggest_map.py --scan scan.json

# data/ is not in the repository; build the dataset first
python research/bulk_scan.py --top 3000 --out data/pypi-top3000.jsonl
python research/suggest_map.py --dataset data/pypi-top3000.jsonl --limit 30
```

```
  1. pytorch-lightning
     1 advisory never fixed
     "PyTorch Lightning is the lightweight PyTorch wrapper for ML researchers..."
     https://pypi.org/project/pytorch-lightning/
```

Unfixed advisories rank highest, because if such a package does turn out to sit
at a trust boundary then the map is actively hiding something dangerous.

An advisory count is a reason to look, never the answer. `num2words` reached the
top of that list with three unfixed advisories, and reading them showed a
maintainer account compromise rather than anything the library does with input —
so it belongs in `[reviewed] not_exposed`, with that noted.

The map also has to stay right as advisories keep arriving.
`research/audit_map.py` reads the other way: it checks the answers the map
already gives against each package's own advisories, and reports a package
cleared as not at a boundary whose advisories cite a boundary weakness, an
exposed package whose advisories reached a worse consequence than its
categories record, and a `why` citing an advisory id OSV has never heard of.
Naming the advisory in a `why` settles a finding either way, acting on it or
saying why it does not count, so silence is the only thing it reports. It runs
weekly with `--strict` alongside the live contract tests, so a new advisory
that contradicts an entry fails that job rather than going unnoticed.

```bash
python research/audit_map.py
python research/audit_map.py --package langchain-core
```
