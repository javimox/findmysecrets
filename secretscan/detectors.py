"""Line-level detection: what looks like a secret within one line of text.

Four rule families, in priority order (when two overlap, the first one wins):

1. Provider patterns: private keys, AWS AKIA/ASIA, GitHub ghp_/github_pat_,
   Slack xoxb-/xoxp-, Stripe sk_live_/rk_live_. High confidence.
2. Connection strings with an embedded password (scheme://user:<password>@host). High.
3. Suspicious assignments: a credential-like name receives a literal. Medium.
4. High-entropy literals that look like random tokens. Low.

Placeholders, references to secret managers and integrity hashes are discarded
(YOUR_API_KEY, <TOKEN>, xxxx, changeme, ${{ secrets.X }}, vault:..., sha512-...).
"""
from __future__ import annotations

import functools
import math
import re
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise
from pathlib import PurePosixPath

HIGH, MEDIUM, LOW = "high", "medium", "low"
MIN_VALUE_LEN = 4


@dataclass(frozen=True)
class Detection:
    """A secret within a line: line[start:end] is the secret value."""

    rule: str
    confidence: str
    start: int
    end: int
    key: str | None = None


# --------------------------------------------------------------------------- #
# Placeholders and external references (not hardcoded secrets)
# --------------------------------------------------------------------------- #
_PLACEHOLDER_RE = re.compile(
    r"""
      your[_\-]                                  # YOUR_API_KEY, your-token-here
    | example | changeme | change[_\-]me | replace[_\-]?me
    | placeholder | dummy | redacted
    | x{4,} | \*{3,} | \.{3,}                     # xxxx, ****, ...
    | ^<.+>$                                     # <TOKEN>
    | ^\$ | \$\{ | \{\{ | \{[\w.]*\} | ^%\w+%$     # $VAR ${VAR} ${{ secrets.X }} {{ x }} {x} %VAR%
    | ^!                                         # YAML tags: !vault, !Ref
    | ^(?:vault:|arn:aws:|op://|ssm:|secretsmanager:|projects/[^/]+/secrets/)
    | ^sha(?:1|256|384|512)-[A-Za-z0-9+/]+=*$       # subresource integrity hash (package-lock.json)
    | ^(?:null|none|nil|true|false|undefined)$
    | ^(.)\1*$                                   # a single repeated character
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_placeholder(value: str) -> bool:
    """True for placeholders and references to an external secret store."""
    return bool(_PLACEHOLDER_RE.search(value))


# --------------------------------------------------------------------------- #
# 1. Provider patterns
# --------------------------------------------------------------------------- #
PROVIDER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("slack-token", re.compile(r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}")),
    ("stripe-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
)


def _provider(line: str) -> list[Detection]:
    return [Detection(rule, HIGH, m.start(), m.end())
            for rule, regex in PROVIDER_RULES
            for m in regex.finditer(line) if not is_placeholder(m.group())]


# --------------------------------------------------------------------------- #
# 2. Connection strings with credentials
# --------------------------------------------------------------------------- #
_CONNECTION_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9+.\-]{1,30}://"   # scheme: postgresql://, mongodb+srv://
    r"[^\s:/?#@'\"]+:"                      # user
    r"(?P<secret>[^\s/?#@'\"]+)@"           # password
    r"[^\s'\"/]+"                           # host
)


def _connection(line: str) -> list[Detection]:
    return [Detection("connection-string", HIGH, m.start("secret"), m.end("secret"))
            for m in _CONNECTION_RE.finditer(line) if not is_placeholder(m.group("secret"))]


# --------------------------------------------------------------------------- #
# 3. Suspicious assignments: password = "...", "api_key": "...", token: str = "..."
# --------------------------------------------------------------------------- #
_ASSIGN_RE = re.compile(
    r"""
    (?P<key>[A-Za-z_$@][\w.$\-]*)          # identifier: password, db.password, apiKey
    ["'\]]{0,2}                            # closing key quote/bracket: "password": / ["password"] =
    (?:\s*:\s*[A-Za-z_][\w.\[\], |]*?)?    # optional type annotation: token: str =
    \s*(?:==|:=|=>|=|:)\s*                 # assignment, comparison or mapping entry
    [rRbBuU]?                              # Python string prefix
    (?P<q>["'`])(?P<value>(?:\\.|[^\s"'`\\])+)(?P=q)   # literal without spaces; \" kept
    """,                                   # (disjoint alternatives: linear, no backtracking blow-up)
    re.VERBOSE,
)

# Configuration formats where values are usually unquoted (.env, YAML, INI...)
_CONFIG_SUFFIXES = {".env", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml"}
_BARE_KV_RE = re.compile(
    r"^\s*(?:-\s+)?(?:export\s+)?(?P<key>[A-Za-z_][\w.\-]*)\s*[:=]\s*(?P<value>[^\s\"'`#][^\s#]*)"
)

_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
# A name word is credential-like if it ends like this (dbpassword, clientsecret,
# accesstoken) or is one of the exact words. Suffixes, not substrings, so that
# secretscan, secretary, tokenizer and author are not flagged.
_SECRET_SUFFIXES = ("password", "passwd", "passphrase", "secret", "token", "apikey",
                    "credential", "credentials")
_SECRET_WORDS = {"pwd", "pass", "passwords", "secrets", "tokens", "secretkey",
                 "privatekey", "accesskey"}
_KEY_QUALIFIERS = {"api", "access", "private", "secret", "signing", "encryption", "master"}
# Names ending like this describe a secret without being one: TOKEN_URL, SECRET_NAME...
_BENIGN_LAST_WORDS = {
    "name", "names", "id", "ids", "url", "uri", "urls", "endpoint", "host", "path", "file",
    "filename", "dir", "type", "field", "label", "prompt", "hint", "message", "env", "var",
    "len", "length", "min", "max", "policy", "regex", "pattern", "header", "format", "count",
    "ttl", "timeout", "expiry", "expires", "ref", "arn", "version", "mode", "placeholder",
}


def is_secret_key(identifier: str) -> bool:
    """Does a variable, argument or key name indicate that its value is a secret?

    >>> is_secret_key("valid_password"), is_secret_key("valid_username"), is_secret_key("TOKEN_URL")
    (True, False, False)
    """
    words = [w.lower() for w in _WORD_RE.findall(identifier)]
    if not words or words[-1] in _BENIGN_LAST_WORDS:
        return False
    for i, w in enumerate(words):
        if w.endswith(_SECRET_SUFFIXES) or w in _SECRET_WORDS:
            return True
        if w == "key" and i > 0 and words[i - 1] in _KEY_QUALIFIERS:
            return True
    return False


@functools.lru_cache(maxsize=256)
def is_config_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.startswith(".env") or PurePosixPath(name).suffix in _CONFIG_SUFFIXES


def _config_value(line: str, path: str) -> re.Match[str] | None:
    return _BARE_KV_RE.match(line) if is_config_file(path) else None


def _assignments(line: str, path: str) -> list[Detection]:
    spans = [(m.group("key"), m.start("value"), m.end("value")) for m in _ASSIGN_RE.finditer(line)]
    if m := _config_value(line, path):
        spans.append((m.group("key"), m.start("value"), m.end("value")))
    return [Detection("hardcoded-credential", MEDIUM, start, end, key)
            for key, start, end in spans
            if end - start >= MIN_VALUE_LEN and is_secret_key(key)
            and not is_placeholder(line[start:end])]


# --------------------------------------------------------------------------- #
# 4. High entropy
# --------------------------------------------------------------------------- #
# Calibrated in S1 on random tokens and on every quoted string of the Python
# standard library and installed packages. Entropy alone flags hundreds of
# identifiers (sha512WithRSAEncryption); with the three conditions below it
# detects 93% of 20-char, 97% of 32-char and 99% of 64-char base62 tokens.
MIN_ENTROPY_LEN = 20
ENTROPY_FACTOR = 0.8       # entropy >= 0.8 * log2(min(len, 64))
MIN_CLASS_CHANGES = 0.4    # share of adjacent characters that change class
MAX_WORDINESS = 0.5        # share of the string made of word-like runs
_TOKEN_CHARSET_RE = re.compile(r"[A-Za-z0-9+/_\-]+={0,2}")
_HEX_RE = re.compile(r"[0-9a-fA-F\-]+")   # hashes, checksums, UUIDs: public data
_QUOTED_LONG_RE = re.compile(r"""(["'`])([^"'`\s]{20,})\1""")
_WORDISH_RE = re.compile(r"[A-Z]?[a-z]{3,}")


def shannon_entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _char_class(ch: str) -> str:
    return "u" if ch.isupper() else "l" if ch.islower() else "d" if ch.isdigit() else "o"


def looks_random(s: str) -> bool:
    """Does the string look like a random token (not an identifier, a hash or a word)?"""
    n = len(s)
    if n < MIN_ENTROPY_LEN or not _TOKEN_CHARSET_RE.fullmatch(s) or _HEX_RE.fullmatch(s):
        return False
    if not (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) and re.search(r"\d", s)):
        return False
    changes = sum(_char_class(a) != _char_class(b) for a, b in pairwise(s)) / (n - 1)
    wordiness = sum(len(w) for w in _WORDISH_RE.findall(s)) / n
    return (shannon_entropy(s) >= ENTROPY_FACTOR * math.log2(min(n, 64))
            and changes >= MIN_CLASS_CHANGES and wordiness < MAX_WORDINESS)


def _entropy(line: str, path: str) -> list[Detection]:
    spans = [(m.start(2), m.end(2)) for m in _QUOTED_LONG_RE.finditer(line)]
    if m := _config_value(line, path):
        spans.append((m.start("value"), m.end("value")))
    return [Detection("high-entropy-string", LOW, s, e) for s, e in spans
            if looks_random(line[s:e]) and not is_placeholder(line[s:e])]


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def detect_line(line: str, path: str = "") -> list[Detection]:
    """Secrets in one line, without overlaps (the higher-priority rule wins)."""
    candidates = _provider(line) + _connection(line) + _assignments(line, path) + _entropy(line, path)
    accepted: list[Detection] = []
    for d in candidates:
        if all(d.end <= a.start or d.start >= a.end for a in accepted):
            accepted.append(d)
    return sorted(accepted, key=lambda d: d.start)


# --------------------------------------------------------------------------- #
# Lexical helpers shared by the pipeline
# --------------------------------------------------------------------------- #
_QUOTED_RE = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\])*)\1""")   # disjoint alternatives: linear
_COMMENT_STARTS = ("#", "//", "--", ";", "/*", "<!--")
_IGNORE_RE = re.compile(r"\s*IGNORE\b")


def string_spans(line: str, path: str = "") -> list[tuple[int, int]]:
    """Spans of the string values on a line: the contents of quoted literals of any
    language, plus the unquoted value of a configuration entry."""
    spans = [(m.start(2), m.end(2)) for m in _QUOTED_RE.finditer(line)]
    if m := _config_value(line, path):
        spans.append((m.start("value"), m.end("value")))
    return spans


def literals(line: str, path: str = "") -> list[tuple[int, int]]:
    """The string values that could hold a secret: short values and placeholders are left out."""
    return [(s, e) for s, e in string_spans(line, path) if e - s >= MIN_VALUE_LEN and not is_placeholder(line[s:e])]


def ignore_marker(line: str) -> bool:
    """True if the line carries the false-positive marker `IGNORE` in a comment.

    The marker must be written in upper case right after a comment start
    (`# IGNORE`, `// IGNORE`, `-- IGNORE`, `/* IGNORE */`, `<!-- IGNORE -->`).
    Text inside quotes is skipped, so a string that contains "# IGNORE" or a
    comment such as "# do not ignore this" never suppresses a finding.
    """
    if "IGNORE" not in line:
        return False
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif any(line.startswith(s, i) and _IGNORE_RE.match(line, i + len(s)) for s in _COMMENT_STARTS):
            return True
        i += 1
    return False
