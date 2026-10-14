"""Scan pipeline: source -> rules -> data flow -> AI -> report.

Sources:
- files:   a recursive walk of files and directories (hidden files included).
- staged:  the Git index, i.e. exactly what the next commit will contain.
- history: lines added by past commits (rules only; "Git never forgets").
- push:    the history rules over the commits a `git push` would upload (pre-push hook).

Paths are always relative to the repository root, so a finding keeps the same id
in every mode, and an id listed in .secretscan-allow marks a false positive.
"""
from __future__ import annotations

import fnmatch
import functools
import hashlib
import io
import itertools
import json
import os
import re
import subprocess
import tokenize
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field, replace
from functools import cached_property
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from .ai import AIConfig, AIError, Models, build_pack
from .detectors import HIGH, LOW, MEDIUM, detect_line, ignore_marker
from .flow import Flow, Origin, Reader, analyze, lexical_slice, module_literals, slice_lines

CONFIDENCE = {LOW: 0, MEDIUM: 1, HIGH: 2}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
             ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"}
MAX_FILE_BYTES = 10_000_000
CONVERTED = (".docx", ".ipynb")                # documents converted to text before scanning
PYTHON = (".py", *CONVERTED)                   # data flow: Python, also pasted in Word or in a notebook
ALLOW_FILE = ".secretscan-allow"               # one finding id per line: reviewed false positives
PACK_CHARS = 6_000          # ~1,500 tokens per model request
CONTEXT_LINES = 3           # window around a change in non-Python files
RULE_WHY = {
    "private-key": "private key block",
    "aws-access-key-id": "AWS access key id format",
    "github-token": "GitHub token format",
    "slack-token": "Slack token format",
    "stripe-key": "Stripe live key format",
    "connection-string": "password embedded in a connection string",
    "hardcoded-credential": "credential-like name receives a literal",
    "high-entropy-string": "random-looking token",
}

_COMMIT_MARKER = "\x1fsecretscan-commit "
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# `git log --raw`: ":<mode> <mode> <old blob> <new blob> <status>\t[<old name>\t]<name>"
_RAW_RE = re.compile(r"^:\d{6} \d{6} ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) [ACMRT]\d*\t(?:[^\t]*\t)?([^\t]*)$")
_DIFF_OPTS = ["--no-color", "--no-ext-diff", "--no-textconv", "--unified=0",
              "--src-prefix=a/", "--dst-prefix=b/"]
_SAFE_REV_OPTS = ("--not", "--all", "--branches", "--remotes", "--tags")
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_ALLOW_RE = re.compile(r"^\s*([0-9a-f]{12})\b", re.MULTILINE)
_C_ESCAPE_RE = re.compile(r'\\([0-7]{3}|[abtnvfr"\\])')
_C_ESCAPES = dict(zip('abtnvfr"\\', '\a\b\t\n\v\f\r"\\', strict=True))


class ScanError(Exception):
    """Usage or Git error (exit code 2)."""


def redact(secret: str) -> dict:
    """Prefix, suffix and length; at most one sixth of the value per side, four characters max."""
    n = len(secret)
    k = min(4, n // 6)
    return {"prefix": secret[:k], "suffix": secret[n - k:] if k else "", "length": n}


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    column: int
    secret: str = field(repr=False)            # in memory only, never serialised
    confidence: str = MEDIUM
    key: str | None = None
    why: list[str] = field(default_factory=list)
    found_by: list[str] = field(default_factory=list)
    commit: str | None = None

    @property
    def id(self) -> str:
        """Stable fingerprint of path + rule + value; it does not depend on the line number."""
        raw = "\0".join((self.file, self.rule, self.secret)).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = {"id": self.id, "rule": self.rule, "confidence": self.confidence, "file": self.file,
             "line": self.line, "column": self.column, "key": self.key, "secret": redact(self.secret),
             "why": self.why, "found_by": self.found_by}
        if self.commit:
            d["commit"] = self.commit
        return d


@dataclass
class Report:
    mode: str
    ai: str = "off"
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    excluded: int = 0               # paths an exclusion names: files, or directories left unwalked
    dirs_skipped: int = 0           # built-in skips: .git, virtual environments, caches
    suppressed: int = 0
    commits_scanned: int = 0
    ai_calls: int = 0
    chat_calls: int = 0
    unverified: int = 0
    incomplete: list[str] = field(default_factory=list)
    _index: dict[tuple[str, int, str], Finding] = field(default_factory=dict, repr=False)
    _hidden: set[tuple[str, int]] = field(default_factory=set, repr=False)

    def add(self, f: Finding) -> None:
        """Add a finding, or enrich the one already reported for the same literal."""
        known = self._index.get((f.file, f.line, f.secret))
        if known is None:
            self._index[(f.file, f.line, f.secret)] = f
            self.findings.append(f)
            return
        known.why += [w for w in f.why if w not in known.why]
        known.found_by += [b for b in f.found_by if b not in known.found_by]
        if CONFIDENCE[f.confidence] > CONFIDENCE[known.confidence]:
            known.confidence = f.confidence

    def hide(self, file: str, line: int) -> None:
        """Count a line whose findings an IGNORE marker suppressed."""
        if (file, line) not in self._hidden:
            self._hidden.add((file, line))
            self.suppressed += 1

    @property
    def exit_code(self) -> int:
        return 1 if self.findings else 3 if self.incomplete else 0

    def summary(self) -> dict:
        s = {"findings": len(self.findings), "files_scanned": self.files_scanned,
             "files_skipped": self.files_skipped, "excluded": self.excluded,
             "dirs_skipped": self.dirs_skipped, "suppressed": self.suppressed, "ai_calls": self.ai_calls,
             "chat_calls": self.chat_calls, "unverified": self.unverified}
        if self.mode in ("history", "push"):
            s["commits_scanned"] = self.commits_scanned
        return s


@dataclass(frozen=True)
class Options:
    excludes: tuple[str, ...] = ()
    suppress: bool = True           # honour IGNORE markers and the allow file (False: audit)
    min_confidence: str = LOW


@dataclass(frozen=True)
class Source:
    path: str
    text: str
    changed: set[int] | None        # None: the whole file is new to the scan; empty: context only
    previous: str | None = None     # the file before the commit (staged mode)

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def in_change(self, n: int) -> bool:
        return self.changed is None or n in self.changed


def _absent(path: str) -> str | None:
    """Reader of an empty snapshot."""
    return None


@dataclass(frozen=True)
class Snapshot:
    """Where other files are read: the working tree or the index, and HEAD in a commit."""
    read: Reader
    before: Reader = _absent


# --------------------------------------------------------------------------- #
# Formats
# --------------------------------------------------------------------------- #
def _docx_text(data: bytes) -> str | None:
    """Paragraphs of a Word document; line breaks and tabs are kept (code pasted in Word)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.getinfo("word/document.xml").file_size > MAX_FILE_BYTES:
                return None
            root = ElementTree.fromstring(z.read("word/document.xml"))  # noqa: S314 (size-capped; expat >= 2.4 limits entity expansion)
    except (KeyError, zipfile.BadZipFile, ElementTree.ParseError, OSError):
        return None
    # Only run content counts: <w:tab> inside <w:pPr> is a tab-stop definition, not a character.
    chars = {_W + "br": "\n", _W + "cr": "\n", _W + "tab": "\t"}
    return "\n".join("".join(e.text or "" if e.tag == _W + "t" else chars.get(e.tag, "")
                             for run in p.iter(_W + "r") for e in run)
                     for p in root.iter(_W + "p"))


def _ipynb_text(data: bytes) -> str | None:
    """A notebook as a Python file: code cells as they are; markdown, outputs and
    IPython magics as comments, so that rules see them and the code still parses."""
    try:
        out: list[str] = []
        for cell in json.loads(data)["cells"]:
            source = "".join(cell.get("source", ""))
            code = cell.get("cell_type") == "code" and not source.startswith("%%")
            out += [line if code and not line.lstrip().startswith(("%", "!")) else f"# {line}"
                    for line in source.splitlines()]
            for output in cell.get("outputs", []):
                text = "".join(output.get("text", "") or output.get("data", {}).get("text/plain", ""))
                out += [f"# {line}" for line in text.splitlines()]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return "\n".join(out)


def to_text(data: bytes, path: str) -> str | None:
    """Text of a supported file; None for binaries and oversized content."""
    if len(data) > MAX_FILE_BYTES:
        return None
    if path.lower().endswith(".docx"):
        return _docx_text(data)
    if path.lower().endswith(".ipynb"):
        return _ipynb_text(data)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8-sig", errors="replace")


def is_excluded(path: str, patterns: tuple[str, ...]) -> bool:
    """Globs over repository-relative paths; `samples` or `samples/` exclude the whole tree."""
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, p.rstrip("/") + "/*") for p in patterns)


# --------------------------------------------------------------------------- #
# Git
# --------------------------------------------------------------------------- #
def _git_bytes(root: Path, *args: str, ok: tuple[int, ...] = (0,)) -> bytes:
    try:
        proc = subprocess.run(["git", "-c", "core.quotePath=false", *args], cwd=root,
                              capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise ScanError("Git is not installed or not in PATH") from exc
    if proc.returncode not in ok:
        raise ScanError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[:200]}")
    return proc.stdout


def _git(root: Path, *args: str) -> str:
    return _git_bytes(root, *args).decode("utf-8", errors="replace")


def repo_root(cwd: Path) -> Path:
    """Repository root, or the directory itself outside a repository."""
    try:
        return Path(_git(cwd, "rev-parse", "--show-toplevel").strip()).resolve()
    except ScanError:
        return cwd.resolve()


def config_excludes(root: Path) -> tuple[str, ...]:
    """Exclusions for commits (staged and history modes): git config --add findmysecrets.exclude 'samples/*'.
    A files scan is an audit of what is there: it leaves out only what --exclude names."""
    try:
        return tuple(_git(root, "config", "--get-all", "findmysecrets.exclude").splitlines())
    except ScanError:
        return ()


def _diff_name(name: str) -> str:
    """A file name as a diff header writes it: git appends a tab when the name holds a space,
    and C-quotes it when it holds a quote, a backslash or a control character (with
    core.quotePath=false, octal escapes are left for control characters only)."""
    name = name.removesuffix("\t")
    if len(name) > 1 and name[0] == name[-1] == '"':
        name = _C_ESCAPE_RE.sub(lambda m: _C_ESCAPES.get(m[1]) or chr(int(m[1], 8)), name[1:-1])
    return name


def iter_added_lines(diff: str) -> Iterator[tuple[str | None, str, int, str]]:
    """(commit, file, line number, content) of every added line in a unified diff."""
    commit: str | None = None
    path: str | None = None
    in_header = False
    lineno = 0
    for raw in diff.split("\n"):
        if raw.startswith(_COMMIT_MARKER):
            commit, path, in_header = raw[len(_COMMIT_MARKER):].strip(), None, False
        elif raw.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and raw.startswith("+++ "):
            target = _diff_name(raw[4:])
            path = None if target == "/dev/null" else target.removeprefix("b/")
        elif m := _HUNK_RE.match(raw):
            lineno, in_header = int(m.group(1)), False
        elif not in_header and path is not None:
            if raw.startswith("+"):
                yield commit, path, lineno, raw[1:].rstrip("\r")
                lineno += 1
            elif raw.startswith(" "):
                lineno += 1


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
def _rel(path: Path, root: Path) -> str:
    """Repository-relative path, the same in every mode (absolute outside the repository)."""
    path = path.resolve()
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()


def _walk(target: Path, root: Path, excludes: tuple[str, ...], report: Report) -> Iterator[Path]:
    if target.is_symlink():
        report.files_skipped += 1
    elif target.is_file():
        yield target
    else:
        for dirpath, dirnames, filenames in os.walk(target):          # does not follow links
            excluded = [d for d in dirnames if is_excluded(_rel(Path(dirpath, d), root) + "/", excludes)]
            report.excluded += len(excluded)                            # pruned, never walked
            report.dirs_skipped += sum(d in SKIP_DIRS for d in dirnames)
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d not in excluded)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if path.is_symlink():
                    report.files_skipped += 1
                else:
                    yield path


def _text(path: str, data: bytes, report: Report) -> str | None:
    """Text to analyse, or None. A binary file is out of scope (skipped); a text file over the
    size limit or a document that cannot be converted leaves the scan incomplete."""
    text = to_text(data, path) if len(data) <= MAX_FILE_BYTES else None
    if text is None:
        report.files_skipped += 1
        if len(data) > MAX_FILE_BYTES and (path.lower().endswith(CONVERTED) or b"\0" not in data[:8192]):
            report.incomplete.append(f"{path}: over {MAX_FILE_BYTES // 1_000_000} MB, not analysed "
                                     "(exclude it if it holds no code or configuration)")
        elif path.lower().endswith(CONVERTED):
            report.incomplete.append(f"{path}: cannot be converted to text, not analysed")
    return text


def _reader(root: Path, rev: str | None, excludes: tuple[str, ...]) -> Reader:
    """Text of a file by repository-relative path, from the working tree (rev None), the
    index (":") or the last commit ("HEAD:"). Excluded or unreadable files read as None."""
    @functools.cache
    def listed() -> frozenset[str]:            # one Git call, so that a miss (`import os`) costs none
        args = ["ls-files", "-z"] if rev == ":" else ["ls-tree", "-r", "-z", "--name-only", "HEAD"]
        try:
            return frozenset(_git(root, *args).split("\0"))
        except ScanError:                      # no commit yet
            return frozenset()

    @functools.cache
    def read(path: str) -> str | None:
        if is_excluded(path, excludes):
            return None
        try:
            if rev is not None:
                return to_text(_git_bytes(root, "show", rev + path), path) if path in listed() else None
            file = root / path
            if file.is_file() and not file.is_symlink() and file.stat().st_size <= MAX_FILE_BYTES:
                return to_text(file.read_bytes(), path)
        except (OSError, ScanError):
            pass
        return None
    return read


def allowed(read: Reader) -> set[str]:
    """Ids of findings reviewed as false positives, listed in ALLOW_FILE at the repository root."""
    return set(_ALLOW_RE.findall(read(ALLOW_FILE) or ""))


def file_sources(paths: list[str], cwd: Path, root: Path, opts: Options, report: Report) -> Iterator[Source]:
    for arg in paths or ["."]:
        target = cwd / arg
        if not target.exists() and not target.is_symlink():
            raise ScanError(f"path does not exist: {arg}")
        for file in _walk(target, root, opts.excludes, report):
            rel = _rel(file, root)
            if is_excluded(rel, opts.excludes):
                report.excluded += 1
                continue
            try:
                with file.open("rb") as fh:
                    data = fh.read(MAX_FILE_BYTES + 1)
            except OSError as exc:
                report.incomplete.append(f"{rel}: cannot be read ({exc.strerror})")
                continue
            if (text := _text(rel, data, report)) is not None:
                yield Source(rel, text, None)


def _literal_values(text: str | None, path: str) -> dict[str, str]:
    return {name: o.value for name, o in module_literals(text, path).items()}


def _importers(root: Path, modules: set[str]) -> list[str]:
    """Python files in the index that name one of these modules, so may import it."""
    names = sorted({PurePosixPath(m).parent.name if m.endswith("/__init__.py") else PurePosixPath(m).stem
                    for m in modules})
    if not names:
        return []
    out = _git_bytes(root, "grep", "--cached", "-l", "-z", "-w", "-F", *(a for n in names for a in ("-e", n)),
                     "--", "*.py", ok=(0, 1))
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p and p not in modules]


def staged_sources(root: Path, snap: Snapshot, opts: Options, report: Report) -> Iterator[Source]:
    """Changed files as staged in the index (unstaged edits on disk are never read), then the
    unchanged Python files that may import a module whose top-level literals changed: a new
    value there can reach a use in them."""
    added: dict[str, set[int]] = {}
    for _, path, lineno, _ in iter_added_lines(_git(root, "diff", "--cached", "-M", *_DIFF_OPTS)):
        added.setdefault(path, set()).add(lineno)
    fields = _git(root, "diff", "--cached", "--name-status", "-z", "-M", "--diff-filter=ACMR").split("\0")
    modules: set[str] = set()
    old_name: dict[str, str] = {}
    i = 0
    while i < len(fields) - 1:
        status, old = fields[i], fields[i + 1]
        path = fields[i + 2] if status[0] in "RC" else old
        old_name[path] = old
        i += 3 if status[0] in "RC" else 2
        if status == "R100":                       # pure rename: nothing new is exposed
            continue
        if is_excluded(path, opts.excludes):
            report.excluded += 1
            continue
        if (text := _text(path, _git_bytes(root, "show", f":{path}"), report)) is None:
            continue
        previous = None if status == "A" else snap.before(old)
        if path.endswith(".py") and _literal_values(text, path) != _literal_values(previous, path):
            modules.add(path)                      # its importers may now receive a new literal
        # Converted documents have no textual diff: the whole document is checked.
        changed = None if path.lower().endswith(CONVERTED) else added.get(path, set())
        yield Source(path, text, changed, previous)
    for path in _importers(root, modules):
        if (text := snap.read(path)) is not None:
            yield Source(path, text, set(), snap.before(old_name.get(path, path)))


# --------------------------------------------------------------------------- #
# Analysis of one source
# --------------------------------------------------------------------------- #
def _flow_finding(src: Source, flow: Flow, decision_p: float | None = None) -> Finding:
    o = flow.origin
    use = f"line {flow.use_line}" if o.path == src.path else f"{src.path}:{flow.use_line}"
    why, by, confidence = [f"{flow.reason} ({use})"], ["flow"], HIGH
    if decision_p is not None:
        why, by, confidence = [*why, f"decision model p={decision_p:.2f}"], ["flow", "decision"], MEDIUM
    return Finding("credential-flow", o.path, o.line, o.col + 1, o.value, confidence, o.name, why, by)


def _context(src: Source, changed: set[int]) -> set[int]:
    """The changed lines and the code tied to them: the Python slice, or for other languages
    (and Python that does not parse) the lines linked by name plus a small window."""
    sliced = slice_lines(src.text, changed) if src.path.endswith(".py") else None
    if sliced is not None:
        return sliced
    window = {n + d for n in changed for d in range(-CONTEXT_LINES, CONTEXT_LINES + 1)}
    return lexical_slice(src.lines, changed) | window


def _units(src: Source, ignored: set[int], candidates: list[Flow]) -> Iterator[list[int]]:
    """Line groups for the models: the slice of a change, or the whole file in chunks."""
    lines = src.lines
    wanted = set(range(1, len(lines) + 1)) if src.changed is None else _context(src, src.changed)
    wanted |= {ln for c in candidates for ln in (c.origin.line, c.use_line)}
    chunk: list[int] = []
    size = 0
    for n in sorted(ln for ln in wanted if 1 <= ln <= len(lines) and ln not in ignored):
        if chunk and size + len(lines[n - 1]) > PACK_CHARS:
            yield chunk
            chunk, size = [], 0
        chunk.append(n)
        size += len(lines[n - 1]) + 8
    if chunk:
        yield chunk


def _review(src: Source, ignored: set[int], flows: list[Flow], models: Models, report: Report) -> None:
    """The decision model judges each weak data-flow candidate; the chat model locates anything else.
    What this file has already reported is masked in the packs, so no model is asked about it again."""
    cfg = models.cfg
    strong = {f.origin for f in flows if f.strong}
    candidates = [f for f in flows if not f.strong and f.origin not in strong]
    for unit in _units(src, ignored, candidates):
        reported = [(o.line, o.col, o.end) for o in strong] + [
            (f.line, f.column - 1, f.column - 1 + len(f.secret)) for f in report.findings if f.file == src.path]
        pack = build_pack(src.path, src.lines, unit, [c for c in candidates if c.origin.line in unit], reported)
        if pack is None:
            continue
        if cfg.mode == "triage":
            scores = models.decide(pack)
            for cid, (_, flow) in pack.candidates.items():
                if scores[cid] >= cfg.threshold:
                    report.add(_flow_finding(src, flow, scores[cid]))
            if scores.get("other", 0.0) < cfg.threshold:
                continue
        hits, unverified = models.investigate(pack)
        report.unverified += unverified
        for lit, kind, reason in hits:
            # A citation of one piece of a folded literal ("tk-" + "91af" + "77bc") stands for the whole
            # value, so it enriches that finding instead of reporting a fragment.
            o = next((f.origin for f in flows
                      if f.origin.line == lit.line and f.origin.col <= lit.start and lit.end <= f.origin.end), None)
            line, col, value = (o.line, o.col, o.value) if o else (lit.line, lit.start, lit.value)
            report.add(Finding(f"ai-{kind}", src.path, line, col + 1, value, MEDIUM,
                               why=[reason or "reported by the chat model"], found_by=["chat"]))


def _rule_findings(src: Source, ignored: set[int], report: Report) -> None:
    for n, line in enumerate(src.lines, 1):
        detections = detect_line(line, src.path) if src.in_change(n) else []
        if detections and n in ignored:
            report.hide(src.path, n)
            continue
        for d in detections:
            report.add(Finding(d.rule, src.path, n, d.start + 1, line[d.start:d.end], d.confidence,
                               d.key, [RULE_WHY[d.rule]], ["rules"]))


def _identity(flow: Flow) -> tuple[str, str, str]:
    return flow.origin.path, flow.origin.value, flow.reason


def _flow_findings(src: Source, snap: Snapshot, opts: Options, ignored: set[int], report: Report) -> list[Flow]:
    """Report strong flows; return the unmarked flows whose literal is in this file, for the models."""
    if not src.path.lower().endswith(PYTHON):
        return []
    flows = analyze(src.text, src.path, snap.read)
    if src.previous is not None:
        # In a commit only new flows count, wherever the change is: the literal, its use or an
        # assignment in between. A reformatted line or a moved block reports nothing.
        before = {_identity(f) for f in analyze(src.previous, src.path, snap.before)}
        flows = [f for f in flows if _identity(f) not in before]

    def marked(o: Origin) -> bool:                 # IGNORE on the literal's line, in whichever file
        if o.path == src.path:
            return o.line in ignored
        lines = (snap.read(o.path) or "").splitlines() if opts.suppress else []
        return o.line <= len(lines) and ignore_marker(lines[o.line - 1])

    kept = []
    for flow in flows:
        if marked(flow.origin):
            if flow.strong:
                report.hide(flow.origin.path, flow.origin.line)
            continue
        if flow.strong:
            report.add(_flow_finding(src, flow))
        if flow.origin.path == src.path:           # the model packs hold this file only
            kept.append(flow)
    return kept


def _ignored(src: Source) -> set[int]:
    """Lines whose comment carries IGNORE. In Python only real comments count, so a
    "# IGNORE" inside a triple-quoted string is text, not a marker."""
    if "IGNORE" not in src.text:
        return set()
    if src.path.lower().endswith(PYTHON):
        try:
            return {t.start[0] for t in tokenize.generate_tokens(io.StringIO(src.text).readline)
                    if t.type == tokenize.COMMENT and ignore_marker(t.string)}
        except (tokenize.TokenError, SyntaxError):          # not Python after all (e.g. a document)
            pass
    return {n for n, line in enumerate(src.lines, 1) if ignore_marker(line)}


def analyze_source(src: Source, snap: Snapshot, opts: Options, models: Models | None, report: Report) -> None:
    """Rules on the changed lines, data flow on the whole file, models on the slice."""
    ignored = _ignored(src) if opts.suppress else set()
    _rule_findings(src, ignored, report)
    flows = _flow_findings(src, snap, opts, ignored, report)
    if models:
        _review(src, ignored, flows, models, report)


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def scan(paths: list[str] | None = None, cwd: Path | None = None, mode: str = "files",
         opts: Options = Options(), ai: AIConfig = AIConfig()) -> Report:
    """Scan files (`mode="files"`) or the Git index (`mode="staged"`)."""
    cwd = (cwd or Path.cwd()).resolve()
    root = repo_root(cwd)
    if mode == "staged" and not (root / ".git").exists():
        raise ScanError("--staged needs a Git repository")
    report = Report(mode, ai.mode)
    if mode == "staged":
        opts = replace(opts, excludes=opts.excludes + config_excludes(root))
        snap = Snapshot(_reader(root, ":", opts.excludes), _reader(root, "HEAD:", opts.excludes))
        sources = staged_sources(root, snap, opts, report)
    else:
        snap = Snapshot(_reader(root, None, opts.excludes))
        sources = file_sources(paths or [], cwd, root, opts, report)
    models = Models(ai) if ai.mode != "off" else None
    active = models
    for src in sources:
        report.files_scanned += 1
        try:
            analyze_source(src, snap, opts, active, report)
        except AIError as exc:            # fail closed: the scan is incomplete and models stop here
            report.incomplete.append(f"{src.path}: {exc}; later files were checked without AI")
            active = None
    if models:
        report.ai_calls, report.chat_calls = models.calls, models.chat_calls
    return _finish(report, opts, allowed(snap.read))


def _finish(report: Report, opts: Options, allow: set[str]) -> Report:
    """Drop the findings listed in the allow file (unless auditing) and those below --min-confidence."""
    kept = [f for f in report.findings if not (opts.suppress and f.id in allow)]
    report.suppressed += len(report.findings) - len(kept)
    threshold = CONFIDENCE[opts.min_confidence]
    report.findings = sorted((f for f in kept if CONFIDENCE[f.confidence] >= threshold),
                             key=lambda f: (f.commit or "", f.file, f.line, f.column))
    return report


def _document_lines(root: Path, log: str, excludes: tuple[str, ...],
                    report: Report) -> Iterator[tuple[str | None, str, int, str]]:
    """Added lines of the Word documents and notebooks in a `git log --raw` output. Their diff is
    binary or JSON, so each version is converted to text and compared with the version before."""
    commit: str | None = None
    for raw in log.split("\n"):
        if raw.startswith(_COMMIT_MARKER):
            commit = raw[len(_COMMIT_MARKER):].strip()
            continue
        m = _RAW_RE.match(raw)
        if not m or not (path := _diff_name(m[3])).lower().endswith(CONVERTED) or is_excluded(path, excludes):
            continue
        if (text := _text(path, _git_bytes(root, "cat-file", "blob", m[2]), report)) is None:
            continue
        old = to_text(_git_bytes(root, "cat-file", "blob", m[1]), path) if m[1].strip("0") else None
        before = set((old or "").splitlines())
        yield from ((commit, path, n, line) for n, line in enumerate(text.splitlines(), 1) if line not in before)


def pushed_revs(updates: str, remote: str) -> list[str]:
    """What `git push` uploads, from the lines the pre-push hook reads on its standard input
    ("<local ref> <local sha> <remote ref> <remote sha>"): the commits of the pushed tips that no
    branch of the remote is known to hold. A branch deletion uploads nothing."""
    tips = [f[1] for f in map(str.split, updates.splitlines()) if len(f) == 4 and f[1].strip("0")]
    return [*tips, "--not", f"--remotes={remote}"] if tips else []


def _pushed_allow(root: Path, revs: Sequence[str]) -> set[str]:
    """Ids in the allow file of the tips being pushed. As the pre-commit hook reads the index, a push
    is judged with the exceptions it carries, never with an uncommitted local edit."""
    ids: set[str] = set()
    for tip in (r for r in revs if not r.startswith("-")):
        data = _git_bytes(root, "show", f"{tip}:{ALLOW_FILE}", ok=(0, 128))      # 128: the tip has none
        ids.update(_ALLOW_RE.findall(data.decode("utf-8", errors="replace")))
    return ids


def scan_history(cwd: Path | None = None, revs: Sequence[str] = ("--all",), opts: Options = Options(),
                 mode: str = "history") -> Report:
    """Lines added by the commits `revs` selects (`git log` syntax; all branches by default).
    Rules only, no models."""
    root = repo_root((cwd or Path.cwd()).resolve())
    report = Report(mode)
    if not revs:
        return report
    for a in revs:
        if a.startswith("-") and not (a in _SAFE_REV_OPTS or a.startswith(("--remotes=", "--branches="))):
            raise ScanError(f"option not allowed in --range: {a}")
    log = _git(root, "log", "-p", "--raw", "--no-abbrev", "--format=%x1fsecretscan-commit %H", *_DIFF_OPTS,
               *revs, "--")
    opts = replace(opts, excludes=opts.excludes + config_excludes(root))
    files: set[str] = set()
    text_lines = (a for a in iter_added_lines(log) if not a[1].lower().endswith(CONVERTED))
    for commit, path, lineno, line in itertools.chain(text_lines, _document_lines(root, log, opts.excludes, report)):
        if is_excluded(path, opts.excludes):
            continue
        files.add(path)
        detections = detect_line(line, path)
        if detections and opts.suppress and ignore_marker(line):
            report.suppressed += 1
            continue
        for d in detections:
            report.add(Finding(d.rule, path, lineno, d.start + 1, line[d.start:d.end], d.confidence,
                               d.key, [RULE_WHY[d.rule]], ["rules"], commit))
    report.files_scanned = len(files)
    report.commits_scanned = log.count(_COMMIT_MARKER)
    return _finish(report, opts, _pushed_allow(root, revs) if mode == "push" else allowed(_reader(root, None, ())))
