# Security

## Reporting a vulnerability

Please report privately through
[GitHub's security advisories](https://github.com/binuka200/package-doctor/security/advisories/new)
rather than opening a public issue.

I'll acknowledge within a few days. This is a small project maintained by one
person, so please be patient with timelines — and if something is being actively
exploited, say so clearly and I'll prioritise it.

## What counts as a vulnerability here

package-doctor reads public APIs and writes a report. It installs nothing,
executes nothing from your dependency tree, and needs no credentials. That
limits the blast radius, but the following are real and worth reporting:

- **A false negative.** A package reported as fine that is in fact carrying
  advisories against the installed version. This is the worst failure this tool
  has: it tells you you're safe when you aren't. It is treated as a security
  bug, not a correctness bug.
- **Cache poisoning.** Anything that lets a malicious API response persist
  misleading results into `~/.cache/package-doctor/`.
- **Code execution from scanned input.** The scanner parses lockfiles and
  AST-parses your source. Neither should ever be able to execute anything.
- **Data leaving the machine that shouldn't.** The tool sends package *names*
  to PyPI, OSV and ecosyste.ms. It should never transmit source code, file
  contents or paths.

## What isn't

- **A package being in the wrong exposure category.** That's a
  [map correction](https://github.com/binuka200/package-doctor/issues/new?template=exposure-map.yml) —
  important, but public, and better discussed in the open.
- **Vulnerabilities in packages the tool reports on.** Report those to the
  package's own maintainers. If the tool is reporting them *wrongly*, that's a
  bug here.

## A note on what this tool is not

It is not a substitute for [`pip-audit`](https://github.com/pypa/pip-audit) in
CI. Use that for per-commit vulnerability gating. This answers a different
question — whether anyone is still around to fix a dependency — on a slower
cadence.
