# Security

## Reporting a vulnerability

Please report privately through
[GitHub's security advisories](https://github.com/binuka200/package-doctor/security/advisories/new)
rather than opening a public issue.

If you would rather not use GitHub, or do not have an account,
**contact@binukajayaweera.dev** reaches the same person.

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
  misleading results into `~/.cache/package-doctor/`. The cache is created
  `0600`, since which packages you scan says something about projects you may
  not have published.
- **Unbounded responses.** Bodies above 32 MB are abandoned mid-stream. Every
  source is a free, unauthenticated third party, and a compromised or
  misbehaving one should not be able to exhaust memory.
- **Code execution from scanned input.** The scanner parses lockfiles and
  AST-parses your source. Neither should ever be able to execute anything.
- **Resource exhaustion from a scanned repository.** Source files above 2 MB
  and dependency files above 32 MB are skipped and reported; both are read
  with a bounded read rather than a size check, and only from regular files,
  so a FIFO or a symlink to a device cannot block or flood the scanner.
  Pathologically nested TOML or JSON is treated as malformed rather than
  allowed to raise. Package names from lockfiles are validated against PEP 503
  and CVE identifiers from advisories against their exact form before either
  reaches a URL, and a lockfile declaring more than 2,000 packages is refused
  rather than fired at the upstream APIs. A repository that gets past any of
  those and hangs or exhausts the scanner is worth reporting.
- **Terminal escape injection.** Versions from lockfiles, file names from the
  scanned tree, and URLs and advisory ids from API responses are all rendered
  to the terminal. Every such string has control and formatting characters
  stripped first, including whole CSI and OSC sequences, so scanned content
  cannot clear the screen, retitle the window, or wrap a row in a hyperlink
  that points somewhere other than it appears to. Output that gets an escape
  sequence through is worth reporting.
- **Anything that makes a finding disappear.** Suppression is a false negative
  wearing a different hat. Cache entries are wrapped in an envelope for exactly
  this reason: an earlier version remembered a 404 as a bare
  `{"__missing__": true}` in the same namespace as real API data, so a response
  with that shape would have removed the package from the report entirely.
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
