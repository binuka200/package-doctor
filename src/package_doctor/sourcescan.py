"""Which dependencies your own code actually imports.

Knowing that `pikepdf` parses untrusted PDFs is useful. Knowing that *your*
upload handler imports it is what turns a watch item into a decision.

The honest limit, stated up front and enforced throughout: an import site is
positive evidence that a package is in play. The absence of one is **not**
evidence that it is unreachable - your dependencies call each other, and a
package you never import can still run on every request. So reachability raises
priority and adds evidence; it never lowers a verdict or marks anything safe.
"""

from __future__ import annotations

import ast
import stat
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from .sources.pypi import normalise

#: Directories that are never the project's own source.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "site-packages", ".eggs", "htmlcov", ".idea", ".vscode",
}

#: Path fragments that mark a test or tooling import. Still reported, but a
#: dependency reachable only from tests is a different risk from one on the
#: request path, and the user should be able to see which they are looking at.
TEST_MARKERS = ("test_", "_test", "tests/", "test/", "conftest.py", "/tests/")

#: Largest source file we will parse, in bytes.
#:
#: Reading and building an AST costs memory and time proportional to file size,
#: and this scanner is pointed at repositories the user did not write. Real
#: hand-written Python is orders of magnitude below this; what sits above it is
#: generated code, vendored bundles, or something designed to waste your
#: afternoon. Skipped files are counted and reported rather than passed over in
#: silence, because "we did not look" must stay distinguishable from "we looked
#: and found nothing".
#:
#: CPython's own parser already rejects pathologically nested source with a
#: SyntaxError, and ast.walk iterates rather than recurses, so size is the
#: remaining lever.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Import name -> PyPI distribution, for the cases where they differ. Used only
#: when the environment cannot answer authoritatively.
MODULE_TO_DIST: dict[str, str] = {
    "yaml": "pyyaml", "cv2": "opencv-python", "pil": "pillow", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "jwt": "pyjwt",
    "jose": "python-jose", "dotenv": "python-dotenv", "magic": "python-magic",
    "docx": "python-docx", "pptx": "python-pptx", "fitz": "pymupdf",
    "openssl": "pyopenssl", "crypto": "pycryptodome", "cryptodome": "pycryptodome",
    "nacl": "pynacl", "serial": "pyserial", "usb": "pyusb", "git": "gitpython",
    "mysqldb": "mysqlclient", "skimage": "scikit-image", "grpc": "grpcio",
    "pkg_resources": "setuptools", "google": "protobuf", "attr": "attrs",
    "zoneinfo": "backports-zoneinfo", "win32api": "pywin32", "win32com": "pywin32",
    "psycopg2": "psycopg2-binary", "memcache": "python-memcached",
    "dns": "dnspython", "jinja2": "jinja2", "markdown_it": "markdown-it-py",
    "ruamel": "ruamel-yaml", "pdfminer": "pdfminer-six", "fake_useragent": "fake-useragent",
    "slugify": "python-slugify", "multipart": "python-multipart",
    "lxml_html_clean": "lxml-html-clean",
    "socks": "pysocks", "OpenSSL": "pyopenssl", "Crypto": "pycryptodome",
    "PIL": "pillow", "Xlib": "python-xlib", "yaml_env_tag": "pyyaml-env-tag",
}


@dataclass
class ImportSite:
    module: str
    file: str      # relative to the project root
    line: int
    in_test: bool
    #: The resolved absolute path, for deduplication across source roots.
    #: Two roots that both contain a file render it under two relative
    #: paths, or under one; neither is a safe key. This is.
    path: str = ""

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def key(self) -> tuple[str, int]:
        return (self.path or self.file, self.line)


@dataclass
class ImportIndex:
    """normalised distribution name -> where the project imports it."""

    sites: dict[str, list[ImportSite]] = field(default_factory=dict)
    files_scanned: int = 0
    files_failed: int = 0
    #: Files skipped for exceeding MAX_FILE_BYTES.
    files_too_large: int = 0
    #: Top-level modules we saw but could not attribute to a distribution.
    unresolved: set[str] = field(default_factory=set)

    def add(self, dist: str, site: ImportSite) -> None:
        self.sites.setdefault(normalise(dist), []).append(site)

    def for_package(self, name: str) -> list[ImportSite]:
        return self.sites.get(normalise(name), [])

    def __bool__(self) -> bool:
        return bool(self.sites)


def _stdlib_names() -> frozenset[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return frozenset(names)
    return frozenset()  # pragma: no cover - 3.9 and earlier are unsupported


def _env_module_map() -> dict[str, list[str]]:
    """Ask the running environment which distribution provides each module.

    Authoritative when the project's dependencies are installed alongside
    package-doctor; frequently empty when they are not, which is why the static
    table above exists as a fallback rather than the other way round.
    """
    try:
        from importlib.metadata import packages_distributions
    except ImportError:  # pragma: no cover
        return {}
    try:
        return packages_distributions()  # type: ignore[no-any-return]
    except Exception:  # pragma: no cover - defensive; this reads the whole env
        return {}


def _top_level(module: str) -> str:
    return module.split(".", 1)[0]


def iter_source_files(root: Path, extra_skips: frozenset[str] = frozenset()) -> list[Path]:
    skip = SKIP_DIRS | set(extra_skips)
    found: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in skip for part in path.parts):
            continue
        found.append(path)
    return found


def extract_imports(source: str) -> list[tuple[str, int]]:
    """Top-level module names imported by a file, with line numbers.

    Relative imports are skipped: `from . import thing` is the project's own
    code, never a dependency.
    """
    # The file is the scanned project's code, not ours, and compiling it
    # reports its lint: an invalid escape like "\s" is a SyntaxWarning on 3.12+
    # and a DeprecationWarning before that. Scanning microsoft/Table-Pretraining
    # printed five `<unknown>:106: SyntaxWarning` lines into the report.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        raise

    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((_top_level(alias.name), node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue
            if node.module:
                out.append((_top_level(node.module), node.lineno))
    return out


def build_index(
    root: Path,
    known_packages: set[str] | None = None,
    max_files: int = 5000,
    max_bytes: int = MAX_FILE_BYTES,
    display_root: Path | None = None,
) -> ImportIndex:
    """Walk a project's source and map its imports onto distribution names.

    ``known_packages`` are the normalised names from the lockfile. A module that
    resolves to something outside that set is the project's own code or an
    uninstalled extra, and is dropped rather than guessed at.

    ``display_root`` is what reported paths are relative to - the project
    directory, normally. A scan walks each package directory as its own
    ``root``, and naming files relative to that produced ``models.py:11`` in a
    project with an ``analytics/models.py`` and a ``zerver/models.py``.
    """
    # A single file is a valid root: `--src app.py` checks that file, and
    # its paths are reported relative to the directory it sits in.
    single = root.is_file()
    display_root = display_root or (root.parent if single else root)
    index = ImportIndex()
    stdlib = _stdlib_names()
    env_map = _env_module_map()
    known = known_packages or set()

    candidates = [root] if single else iter_source_files(root)
    for path in candidates[:max_files]:
        try:
            # Only regular files are read. A FIFO named evil.py blocks open()
            # until something writes to it, and a symlink to /dev/zero reads
            # forever - both are things a hostile checkout can contain, and
            # neither shows up in the size check because a device reports zero.
            if not stat.S_ISREG(path.stat().st_mode):
                index.files_failed += 1
                continue
            # Bounded read rather than a size check followed by read_text():
            # the file can grow between the two, and the cap is the point.
            with path.open("rb") as fh:
                raw = fh.read(max_bytes + 1)
            if len(raw) > max_bytes:
                index.files_too_large += 1
                continue
            imports = extract_imports(raw.decode("utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError, RecursionError):
            index.files_failed += 1
            continue

        index.files_scanned += 1
        rel = _relative(path, display_root, root)
        in_test = any(marker in rel.replace("\\", "/") for marker in TEST_MARKERS)

        for module, line in imports:
            if not module or module in stdlib:
                continue

            candidates: list[str] = []
            for dist in env_map.get(module, ()):
                candidates.append(dist)
            mapped = MODULE_TO_DIST.get(module) or MODULE_TO_DIST.get(module.lower())
            if mapped:
                candidates.append(mapped)
            candidates.append(module)

            resolved = None
            for candidate in candidates:
                if not known or normalise(candidate) in known:
                    resolved = candidate
                    break
            if resolved is None:
                index.unresolved.add(module)
                continue

            index.add(resolved, ImportSite(module, rel, line, in_test, str(path.resolve())))

    # Keep sites deterministic and readable: first occurrence per file.
    for dist, sites in index.sites.items():
        seen: dict[str, ImportSite] = {}
        for site in sites:
            if site.file not in seen or site.line < seen[site.file].line:
                seen[site.file] = site
        index.sites[dist] = sorted(seen.values(), key=lambda s: (s.in_test, s.file, s.line))

    return index


def _relative(path: Path, *roots: Path) -> str:
    """The path relative to the first root that contains it, forward slashes.

    A root that *is* the path - a single-file ``--src`` - is skipped: relative
    to itself a file is ".", which rendered ``--src app.py`` as ``.:7`` when
    the file sat outside the scanned project. Outside every root the path is
    given relative to the working directory, which is where the user typed
    it, and failing that in full.
    """
    # The project root first, then the working directory, then the root
    # that was walked: a --src outside the project renders as the user would
    # type it (`core/models/user.py`) rather than relative to itself
    # (`models/user.py`), which loses the directory that identifies it.
    display, *walked = roots
    for root in (display, Path.cwd(), *walked):
        if root == path:
            continue
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            continue
    return str(path)


def prune_nested_roots(roots: list[Path]) -> list[Path]:
    """Drop every root that lies inside another, and repeats.

    Auto-detection returns each package directory and the project root when
    it holds a script - `core` and `.` for a layout with `core/__init__.py`
    and `app.py` - and the user can pass overlapping `--src` values too. A
    file under two roots was walked twice and reported twice, with
    flask-restful showing 65 import sites where there were 33. Walking only
    the outermost roots removes the double count and the double work.
    """
    resolved: list[Path] = []
    for root in roots:
        candidate = Path(root).expanduser().resolve()
        if candidate not in resolved:
            resolved.append(candidate)
    kept: list[Path] = []
    for candidate in resolved:
        inside_another = any(
            other != candidate and _is_within(candidate, other) for other in resolved
        )
        if not inside_another:
            kept.append(candidate)
    return kept


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return root.is_dir()


def merge_sites(parts: list[list[ImportSite]]) -> list[ImportSite]:
    """Combine sites from several roots, one entry per file and line.

    Keyed on the resolved path, not the rendered one; ordering matches a
    single index so the output does not depend on which root came first.
    """
    seen: dict[tuple[str, int], ImportSite] = {}
    for sites in parts:
        for site in sites:
            seen.setdefault(site.key, site)
    return sorted(seen.values(), key=lambda s: (s.in_test, s.file, s.line))


def detect_source_roots(root: Path) -> list[Path]:
    """Where a project's own code most likely lives.

    Scanning the whole tree would work but pulls in vendored copies and example
    directories, so prefer the conventional layouts when they are present.
    """
    candidates: list[Path] = []
    src = root / "src"
    if src.is_dir():
        candidates.append(src)
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        if not child.is_dir() or child.name in SKIP_DIRS or child == src:
            continue
        # A package directory, or a conventional test directory - test suites
        # frequently have no __init__.py, and a dependency reached only from
        # tests is still worth telling the user about.
        if (child / "__init__.py").is_file() or child.name in ("tests", "test"):
            candidates.append(child)
    if any(root.glob("*.py")):
        candidates.append(root)
    return prune_nested_roots(candidates or [root])
