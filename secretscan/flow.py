"""Data flow for Python: a secret is recognised by where it goes, not by its name.

    string literal  ->  variables that copy it  ->  the use that gives it away

Strong uses (reported without AI):
  - passed as a credential-named argument: connect(password=x), auth=x
  - compared with what the user typed through getpass(): typed == x
  - stored under a credential key: {"Authorization": f"Bearer {x}"}, headers["X-Api-Key"] = x
  - fallback of an environment lookup for a credential-named variable:
    SECRET_KEY = os.environ.get("SECRET_KEY", "...")
Weak uses (candidates for the decision model):
  - positional argument, other than the first, of a login/connect-style call

Scoping follows Python: a name bound in a function is local to it unless declared
global/nonlocal; otherwise it resolves in the enclosing functions, then the module
(class bodies are skipped, as in Python). Within a scope the reaching value is the
last binding before the use; branches are not merged (straight-line approximation).
Given a reader for the other files of the snapshot, `from settings import X` and
`import settings` + `settings.X` reach the literal assigned at the top of settings.py.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import PurePosixPath

from .detectors import MIN_VALUE_LEN, is_placeholder, is_secret_key

SINK_CALLS = {"connect", "login", "authenticate", "auth", "signin", "sign_in",
              "HTTPBasicAuth", "HTTPDigestAuth", "BasicAuth"}
LAST_ARG_SINKS = {"set_password"}    # user.set_password(pw), keyring.set_password(service, user, pw)
CREDENTIAL_KEYS = {"auth", "authorization", "proxy-authorization"}
SECRET_INPUTS = {"getpass"}
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_STRING_START_RE = re.compile(r"""[rRbBuUfF]{0,2}(?:\"\"\"|'''|"|')""")

Reader = Callable[[str], str | None]       # repository-relative path -> text of that file


@dataclass(frozen=True)
class Origin:
    line: int
    col: int            # column where the value starts (characters, 0-based)
    name: str
    value: str
    path: str = ""      # file of the literal: the analysed file, or a module it imports
    end: int = 0        # column where the literal expression ends ("tk-" + "91af" as a whole)


@dataclass(frozen=True)
class Flow:
    origin: Origin
    use_line: int
    reason: str
    strong: bool


@dataclass(frozen=True)
class _Binding:
    pos: tuple[int, int]
    origins: frozenset[Origin]
    secret_input: bool = False
    module: str | None = None           # `import settings`: path of settings.py


@dataclass
class _Scope:
    node: ast.AST
    parent: _Scope | None
    nodes: list[ast.AST]                # evaluated in this scope (nested scopes not entered)
    names: set[str] = field(default_factory=set)
    bindings: dict[str, list[_Binding]] = field(default_factory=dict)


def _fold(node: ast.AST) -> str | None:
    """Value of a string literal, also when split: "ab" + "cd"."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _fold(node.left), _fold(node.right)
        return a + b if a is not None and b is not None else None
    return None


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _env_default(call: ast.Call) -> ast.expr | None:
    """Fallback of an environment lookup: the "..." of os.getenv("K", "...") or os.environ.get("K", "...")."""
    owner = getattr(call.func, "value", None)
    name = _call_name(call)
    if name != "getenv" and not (name == "get" and getattr(owner, "attr", getattr(owner, "id", "")) == "environ"):
        return None
    if len(call.args) > 1:
        return call.args[1]
    return next((k.value for k in call.keywords if k.arg == "default"), None)


def _literal_origin(node: ast.expr, name: str, lines: list[str], path: str) -> Origin | None:
    """Origin for a string literal that could be a secret; None for short values and placeholders."""
    value = _fold(node)
    if value is None or len(value) < MIN_VALUE_LEN or is_placeholder(value):
        return None
    line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
    encoded = line.encode()                                            # ast columns count UTF-8 bytes
    col = len(encoded[:node.col_offset].decode(errors="ignore"))
    start = line.find(value[:8], col)
    if start < 0:                                                    # concatenated or escaped literal
        m = _STRING_START_RE.match(line, col)
        start = m.end() if m else col
    end = len(encoded[:node.end_col_offset].decode(errors="ignore")) if node.end_lineno == node.lineno else len(line)
    return Origin(node.lineno, start, name, value, path, end)


def _credential_key(name: str) -> bool:
    return is_secret_key(name) or name.lower() in CREDENTIAL_KEYS


def _secret_shaped(origins: frozenset[Origin], key: str) -> frozenset[Origin]:
    """Under a key, a phrase is a label ({"password": "Enter your password"}), not a secret;
    an Authorization value may carry its scheme ("Bearer <token>")."""
    words = 2 if key.lower() in CREDENTIAL_KEYS else 1
    return frozenset(o for o in origins if len(o.value.split()) <= words)


def _own_nodes(scope: ast.AST):
    """Nodes evaluated in this scope; nested scopes are yielded but not entered."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPE_NODES):
            stack.extend(ast.iter_child_nodes(node))


class _Analyzer:
    def __init__(self, tree: ast.Module, lines: list[str], path: str, read: Reader | None):
        self.lines, self.path, self.read = lines, path, read
        self.scopes: list[_Scope] = []
        self.flows: set[Flow] = set()
        self._modules: dict[str, dict[str, Origin]] = {}
        self._build(tree, None)
        for scope in self.scopes:          # parents are built before their children
            self._bind(scope)
        for scope in self.scopes:
            self._sinks(scope)

    # -- scopes ------------------------------------------------------------- #
    def _build(self, node: ast.AST, parent: _Scope | None) -> None:
        scope = _Scope(node, parent, list(_own_nodes(node)))
        self.scopes.append(scope)
        declared = set()
        for n in scope.nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                scope.names.add(n.id)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                declared.update(n.names)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                scope.names.update((a.asname or a.name).split(".")[0] for a in n.names)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope.names.add(n.name)
        if isinstance(node, _FUNCTIONS):
            scope.names.update(a.arg for a in ast.walk(node.args) if isinstance(a, ast.arg))
        scope.names -= declared
        # Class bodies are not visible from the methods defined inside them.
        child_parent = parent if isinstance(node, ast.ClassDef) else scope
        for n in scope.nodes:
            if isinstance(n, _SCOPE_NODES):
                self._build(n, child_parent)

    def _resolve(self, scope: _Scope | None, name: str, pos: tuple[int, int] | None) -> _Binding | None:
        """Binding that reaches `name` at `pos`; outer scopes contribute their final binding."""
        while scope is not None:
            if name in scope.names:
                found = [b for b in scope.bindings.get(name, []) if pos is None or b.pos < pos]
                return found[-1] if found else None
            scope, pos = scope.parent, None
        return None

    def _origins(self, expr: ast.expr, scope: _Scope, name: str) -> frozenset[Origin]:
        if _fold(expr) is not None:
            origin = _literal_origin(expr, name, self.lines, self.path)
            return frozenset({origin} if origin else ())
        if isinstance(expr, ast.Call):        # a computed value is not a hardcoded secret...
            fallback = _env_default(expr)     # ...but the literal fallback of os.getenv() is
            return self._origins(fallback, scope, name) if fallback is not None else frozenset()
        if any(isinstance(n, ast.Call) for n in ast.walk(expr)):
            return frozenset()
        found: set[Origin] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and (b := self._resolve(scope, n.id, (n.lineno, n.col_offset))):
                found |= b.origins
            elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and (b := self._resolve(scope, n.value.id, (n.lineno, n.col_offset))) and b.module \
                    and (origin := self._exports(b.module).get(n.attr)):
                found.add(origin)
        return frozenset(found)

    def _bind(self, scope: _Scope) -> None:
        """Bindings of a scope in source order, so that each value sees the earlier ones."""
        for pos, name, value in sorted(self._events(scope), key=lambda e: e[0]):
            if isinstance(value, _Binding):
                binding = value
            else:
                origins = self._origins(value, scope, name) if value is not None else frozenset()
                binding = _Binding(pos, origins, isinstance(value, ast.Call) and _call_name(value) in SECRET_INPUTS)
            scope.bindings.setdefault(name, []).append(binding)

    def _events(self, scope: _Scope) -> list[tuple[tuple[int, int], str, ast.expr | _Binding | None]]:
        """(position, name, assigned value) of every binding: assignments, imports, and other
        stores whose value is unknown (for, with, unpacking...)."""
        events: list[tuple[tuple[int, int], str, ast.expr | _Binding | None]] = []
        assigned: set[int] = set()
        for n in scope.nodes:
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if isinstance(t, ast.Name):
                        events.append(((t.lineno, t.col_offset), t.id, n.value))
                        assigned.add(id(t))
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                events += [(binding.pos, name, binding) for name, binding in self._imports(n)]
        events += [((n.lineno, n.col_offset), n.id, None) for n in scope.nodes
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and id(n) not in assigned]
        return events

    # -- other files ---------------------------------------------------------- #
    def _imports(self, node: ast.Import | ast.ImportFrom) -> Iterator[tuple[str, _Binding]]:
        """Bindings of an import: a literal defined in another file, or a module."""
        pos = (node.lineno, node.col_offset)
        if isinstance(node, ast.ImportFrom):
            module = self._module_path(node.module, node.level)
            exports = self._exports(module) if module else {}
            for a in node.names:
                origin = exports.get(a.name)
                yield a.asname or a.name, _Binding(pos, frozenset({origin} if origin else ()))
        else:
            for a in node.names:
                if a.asname or "." not in a.name:            # `import a.b` binds `a`, not a.b
                    yield a.asname or a.name, _Binding(pos, frozenset(), module=self._module_path(a.name, 0))

    def _module_path(self, module: str | None, level: int) -> str | None:
        """File of an imported module in the same snapshot: from the repository root or the
        importing directory, or relative to the importing package (`from .settings import X`)."""
        if self.read is None or not module:
            return None
        here = PurePosixPath(self.path).parent
        for _ in range(level - 1):
            here = here.parent
        for base in ([here] if level else [PurePosixPath(), here]):
            stem = base.joinpath(*module.split("."))
            for candidate in (stem.with_suffix(".py"), stem / "__init__.py"):
                if self.read(candidate.as_posix()) is not None:
                    return candidate.as_posix()
        return None

    def _exports(self, module: str) -> dict[str, Origin]:
        if module not in self._modules:
            self._modules[module] = module_literals(self.read(module) if self.read else None, module)
        return self._modules[module]

    # -- sinks -------------------------------------------------------------- #
    def _add(self, origins: frozenset[Origin], line: int, reason: str, strong: bool) -> None:
        self.flows.update(Flow(o, line, reason, strong) for o in origins)

    def _is_secret_input(self, expr: ast.AST, scope: _Scope) -> bool:
        if isinstance(expr, ast.Call):
            return _call_name(expr) in SECRET_INPUTS
        if isinstance(expr, ast.Name):
            b = self._resolve(scope, expr.id, (expr.lineno, expr.col_offset))
            return bool(b and b.secret_input)
        return False

    def _sinks(self, scope: _Scope) -> None:
        for n in scope.nodes:
            if isinstance(n, ast.Call):
                self._call_sink(n, scope)
            elif isinstance(n, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in n.ops):
                self._compare_sink(n, scope)
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values, strict=True):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        self._key_sink(k.value, v, n.lineno, scope)
            elif isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                self._assign_sink(n, n.value, scope)

    def _assign_sink(self, n: ast.Assign | ast.AnnAssign, value: ast.expr, scope: _Scope) -> None:
        for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
            if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str):
                self._key_sink(t.slice.value, value, n.lineno, scope)
            elif isinstance(t, ast.Name) and _credential_key(t.id) and isinstance(value, ast.Call) \
                    and (fallback := _env_default(value)) is not None:
                self._add(self._origins(fallback, scope, t.id), n.lineno,
                          f"fallback of {ast.unparse(value.func)}() for {t.id}", True)

    def _compare_sink(self, n: ast.Compare, scope: _Scope) -> None:
        for a, b in pairwise([n.left, *n.comparators]):
            for typed, other in ((a, b), (b, a)):
                if self._is_secret_input(typed, scope):
                    self._add(self._origins(other, scope, "compared value"), n.lineno,
                              "compared with the password read by getpass()", True)

    def _key_sink(self, key: str, value: ast.expr, line: int, scope: _Scope) -> None:
        if _credential_key(key):
            self._add(_secret_shaped(self._origins(value, scope, key), key), line,
                      f"stored under key '{key}'", True)

    def _call_sink(self, call: ast.Call, scope: _Scope) -> None:
        name = _call_name(call)
        for kw in call.keywords:
            if kw.arg and _credential_key(kw.arg):
                self._add(self._origins(kw.value, scope, kw.arg), call.lineno,
                          f"passed as {kw.arg}= to {name}()", True)
        if name in LAST_ARG_SINKS and call.args:
            n = len(call.args)
            self._add(self._origins(call.args[-1], scope, f"{name}() argument {n}"), call.lineno,
                      f"argument {n} of {name}()", True)
        elif name in SINK_CALLS:
            for i, arg in enumerate(call.args[1:], start=2):
                self._add(self._origins(arg, scope, f"{name}() argument {i}"), call.lineno,
                          f"argument {i} of {name}()", False)


def module_literals(source: str | None, path: str) -> dict[str, Origin]:
    """Top-level names of a module whose final value is a string literal: what another
    file reaches with `from module import NAME`."""
    try:
        body = ast.parse(source).body if source else []
    except (SyntaxError, ValueError):
        return {}
    lines = source.splitlines() if source else []
    found: dict[str, Origin] = {}
    for st in body:
        if isinstance(st, (ast.Assign, ast.AnnAssign)) and st.value is not None:
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                if isinstance(t, ast.Name):
                    found.pop(t.id, None)                   # a later non-literal value replaces it
                    if origin := _literal_origin(st.value, t.id, lines, path):
                        found[t.id] = origin
    return found


def analyze(source: str, path: str = "", read: Reader | None = None) -> list[Flow]:
    """Flows from string literals to credential uses; [] if the source is not Python.

    `path` is the file's repository-relative path; with `read`, imported names are
    followed into the other files of the same snapshot.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    flows = _Analyzer(tree, source.splitlines(), path, read).flows
    return sorted(flows, key=lambda f: (f.origin.path, f.origin.line, f.origin.col, f.use_line))


# --------------------------------------------------------------------------- #
# Context slice for diffs
# --------------------------------------------------------------------------- #
_HEADER_FIELDS = ("test", "iter", "target", "items", "subject")


def _names(nodes) -> set[str]:
    return {n.id for node in nodes if isinstance(node, ast.AST)
            for n in ast.walk(node) if isinstance(n, ast.Name)}


_Func = ast.FunctionDef | ast.AsyncFunctionDef
_Unit = tuple[int, int, set[str], _Func | None]


def _units(tree: ast.Module) -> list[_Unit]:
    """(first line, last line, names, enclosing function) per simple statement or block header."""
    units: list[_Unit] = []

    def visit(body: list[ast.stmt], func: _Func | None) -> None:
        for st in body:
            block = getattr(st, "body", None)
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(st.body, st)
            elif isinstance(st, ast.ClassDef):
                visit(st.body, func)
            elif isinstance(block, list) and block:                  # if, for, while, with, try, match
                header = [getattr(st, f, None) for f in _HEADER_FIELDS]
                parts = [p for h in header for p in (h if isinstance(h, list) else [h])]
                units.append((st.lineno, max(st.lineno, block[0].lineno - 1), _names(parts), func))
                blocks = [block, getattr(st, "orelse", []), getattr(st, "finalbody", [])]
                blocks += [h.body for h in getattr(st, "handlers", [])]
                blocks += [c.body for c in getattr(st, "cases", [])]
                for block in blocks:
                    visit(block, func)
            else:
                units.append((st.lineno, st.end_lineno or st.lineno, _names([st]), func))

    visit(tree.body, None)
    return units


def slice_lines(source: str, changed: set[int], hops: int = 2) -> set[int] | None:
    """Lines connected to the changed ones through definitions and uses; None if not Python.

    From the changed statements, the variables they define or use are followed
    `hops` times to every statement that defines or uses them, and enclosing
    function headers are added. The model sees the logic of the change, not the file.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    units = _units(tree)
    variables = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    picked = {i for i, (a, b, _, _) in enumerate(units) if any(a <= ln <= b for ln in changed)}
    frontier = set(picked)
    for _ in range(hops):
        wanted = set().union(*(units[i][2] for i in frontier)) & variables
        frontier = {j for j, u in enumerate(units) if j not in picked and u[2] & wanted}
        picked |= frontier
    lines = set(changed)
    for i in picked:
        first, last, _, func = units[i]
        lines.update(range(first, last + 1))
        if func is not None:
            lines.add(func.lineno)
    return lines


_ASSIGNED_LITERAL_RE = re.compile(r"""([A-Za-z_$][\w$]*)["']?\s*(?::=|=|:)\s*[rbuRBU]?["'`]""")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")


def lexical_slice(lines: list[str], changed: set[int], per_name: int = 3) -> set[int]:
    """Any language, by names alone: the changed lines, the lines that assign a literal to a
    name the change uses, and the lines that use a name the change assigns a literal to
    (at most `per_name` lines per name)."""
    changed_text = [lines[n - 1] for n in changed if 1 <= n <= len(lines)]
    used = {w for text in changed_text for w in _IDENTIFIER_RE.findall(text)}
    assigned = {w for text in changed_text for w in _ASSIGNED_LITERAL_RE.findall(text)}
    picked, taken = set(changed), Counter[str]()
    for n, line in enumerate(lines, 1):
        if n in changed:
            continue
        defines = {w for w in _ASSIGNED_LITERAL_RE.findall(line) if w in used}
        for name in defines | (assigned & set(_IDENTIFIER_RE.findall(line))):
            if taken[name] < per_name:
                taken[name] += 1
                picked.add(n)
    return picked
