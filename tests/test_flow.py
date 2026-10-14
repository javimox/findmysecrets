"""Data flow: a secret is recognised by where it goes; and the diff slice."""
import textwrap
import time

import pytest

from conftest import ROOT, kv, scan_snippet
from secretscan.flow import analyze, lexical_slice, slice_lines
from secretscan.scanner import Options, scan


def flows(source: str) -> list[tuple[int, str, int, bool]]:
    return [(f.origin.line, f.origin.value, f.use_line, f.strong) for f in analyze(textwrap.dedent(source))]


# --------------------------------------------------------------------------- #
# Strong uses: reported without AI
# --------------------------------------------------------------------------- #
def test_reference_file_compared_with_getpass():
    [flow] = analyze((ROOT / "samples" / "app.py").read_text())
    assert (flow.origin.line, flow.origin.name, flow.use_line) == (7, "valid_password", 13)
    assert flow.strong and "getpass()" in flow.reason


def test_user_name_compared_with_input_is_not_a_secret():
    assert flows("""
        name = "admin-01"
        if input("user: ") == name:
            pass
    """) == []


@pytest.mark.parametrize("source, reason", [
    ('v = "weird-value-11"\ndb.connect(password=v)\n', "passed as password= to connect()"),
    ('v = "weird-value-11"\nrequests.get(url, auth=v)\n', "passed as auth= to get()"),
    ('v = "weird-value-11"\nh = {"Authorization": f"Bearer {v}"}\n', "stored under key 'Authorization'"),
    ('v = "weird-value-11"\nh = {}\nh["X-Api-Key"] = v\n', "stored under key 'X-Api-Key'"),
    ('import getpass\nv = "weird-value-11"\nok = getpass.getpass() == v\n',
     "compared with the password read by getpass()"),
])
def test_strong_uses(source, reason):
    [flow] = analyze(source)
    assert flow.strong and flow.reason == reason and flow.origin.value == "weird-value-11"


def test_a_literal_passed_directly_is_a_flow_also_with_spaces():
    """The rules skip values with spaces (messages); the use tells a passphrase apart."""
    passphrase = "correct horse " + "battery staple"
    [f] = scan_snippet(f'db.connect(password="{passphrase}")\n').findings
    assert (f.rule, f.secret, f.found_by) == ("credential-flow", passphrase, ["flow"])
    [f] = scan_snippet("db.connect(" + kv("password", "weird-value-11", sep="=") + ")\n").findings
    assert f.found_by == ["rules", "flow"]


def test_set_password_takes_the_password_last():
    """Django user.set_password(pw), keyring.set_password(service, user, pw)."""
    [direct] = analyze('user.set_password("Tr0ub4dor&3x")\n')
    assert direct.strong and direct.reason == "argument 1 of set_password()"
    [stored] = analyze('value = "Tr0ub4dor&3x"\nkeyring.set_password("mail-service", "jm", value)\n')
    assert stored.strong and stored.origin.value == "Tr0ub4dor&3x" and stored.reason == "argument 3 of set_password()"


def test_copies_concatenation_and_fstrings_keep_the_origin():
    assert flows("""
        first = "secret-part-1"
        alias = first
        joined = alias + "-x"
        db.connect(password=joined)
    """) == [(2, "secret-part-1", 5, True)]
    assert flows('tok = "tk-" + "91af" + "77bc"\nh = {"Authorization": f"Bearer {tok}"}\n') == [
        (1, "tk-91af77bc", 2, True)]


def test_sink_inside_a_class_method_uses_the_module_literal():
    assert flows("""
        X = "Zq81-mnbv-local"
        class Repo:
            def open(self):
                return psycopg2.connect(host="db", password=X)
    """) == [(2, "Zq81-mnbv-local", 5, True)]


def test_closure_reads_the_enclosing_function():
    assert flows("""
        def outer():
            value = "cl0sure-val"
            def inner():
                return db.connect(password=value)
            return inner
    """) == [(3, "cl0sure-val", 5, True)]


# --------------------------------------------------------------------------- #
# Weak uses: candidates for the decision model
# --------------------------------------------------------------------------- #
def test_positional_argument_is_only_a_candidate():
    assert flows("""
        mailbox = "misecretpass"
        server.login("alerts@acme.test", mailbox)
        db.login("admin", "S3cr3t-2026")
    """) == [(2, "misecretpass", 3, False), (4, "S3cr3t-2026", 4, False)]


def test_first_positional_argument_is_never_a_candidate():
    assert flows('host = "db.internal"\ndb.connect(host, port=5432)\n') == []


# --------------------------------------------------------------------------- #
# What must NOT be linked
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("source", [
    # same name in another scope: the function uses its own value
    'conf_v = "module-level-1"\ndef f():\n    conf_v = os.environ["P"]\n    db.connect(password=conf_v)\n',
    # reassigned from the environment before the use
    'v = "old-hardcoded-778"\nv = os.getenv("DB_PASSWORD")\ndb.connect(password=v)\n',
    # class attributes are not visible from methods by bare name
    'class C:\n    pw = "S3cr3t-classattr"\n    def f(self):\n        return connect(password=pw)\n',
    # argument names that only contain "auth" or "token"
    'writer = "Jane-Austen-1775"\nBook(author=writer)\n',
    'name = "bert-base-uncased"\npipeline("ner", tokenizer=name)\n',
    # computed values and placeholders are not hardcoded secrets
    'v = load_secret("db")\ndb.connect(password=v)\n',
    'v = "${DB_PASSWORD}"\ndb.connect(password=v)\n',
    # a value that is only printed
    'release = "release-2026-10"\nprint(release)\n',
])
def test_not_linked(source):
    assert analyze(source) == []


def test_global_declaration_reaches_the_module_value():
    assert flows("""
        tval = "glob-al-9921"
        def use():
            global tval
            db.connect(token=tval)
    """) == [(2, "glob-al-9921", 5, True)]


# --------------------------------------------------------------------------- #
# Fallbacks of environment lookups: SECRET_KEY = os.environ.get("SECRET_KEY", "...")
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("source, reason", [
    ('import os\nSECRET_KEY = os.environ.get("SECRET_KEY", "dj-insecure-q9X2w")\n',
     "fallback of os.environ.get() for SECRET_KEY"),
    ('from os import getenv\npassword = getenv("DB_PASSWORD", default="dev-pw-7781")\n',
     "fallback of getenv() for password"),
    ('import os\nv = os.getenv("DB_TAG", "Zq81-mnbv-2026")\ndb.connect(password=v)\n',
     "passed as password= to connect()"),
])
def test_fallback_of_an_environment_lookup(source, reason):
    [flow] = analyze(source)
    assert (flow.origin.line, flow.reason, flow.strong) == (2, reason, True)


@pytest.mark.parametrize("source", [
    'import os\npassword = os.getenv("DB_PASSWORD")\n',                # no fallback
    'import os\npassword = os.getenv("DB_PASSWORD", "changeme")\n',    # placeholder
    'import os\nlevel = os.getenv("LOG_LEVEL", "warning")\n',          # not a credential
    'password = config.get("database", "password")\n',                 # configparser: section, option
])
def test_lookups_that_are_not_hardcoded_secrets(source):
    assert analyze(source) == []


# --------------------------------------------------------------------------- #
# Names imported from other files of the same snapshot
# --------------------------------------------------------------------------- #
SETTINGS = 'DB_TAG = "Zq81-mnbv-2026"\n'


@pytest.mark.parametrize("source", [
    "from settings import DB_TAG\ndb.connect(password=DB_TAG)\n",
    "import settings\ndb.connect(password=settings.DB_TAG)\n",
    "import settings as s\ndb.connect(password=s.DB_TAG)\n",
    "def f():\n    from settings import DB_TAG as t\n    return db.connect(password=t)\n",
])
def test_imported_literal_reaches_a_use_in_another_file(source):
    [flow] = analyze(source, "app.py", {"settings.py": SETTINGS}.get)
    assert (flow.origin.path, flow.origin.line, flow.origin.col, flow.origin.value) == (
        "settings.py", 1, 10, "Zq81-mnbv-2026")


@pytest.mark.parametrize("importer, statement, module", [
    ("pkg/app.py", "from .settings import DB_TAG", "pkg/settings.py"),
    ("pkg/sub/app.py", "from ..settings import DB_TAG", "pkg/settings.py"),
    ("tools/app.py", "from settings import DB_TAG", "tools/settings.py"),     # a script next to its module
    ("app.py", "from conf.settings import DB_TAG", "conf/settings.py"),
    ("app.py", "from conf import DB_TAG", "conf/__init__.py"),
])
def test_module_resolution(importer, statement, module):
    [flow] = analyze(f"{statement}\ndb.connect(password=DB_TAG)\n", importer, {module: SETTINGS}.get)
    assert flow.origin.path == module


@pytest.mark.parametrize("module_text", [
    SETTINGS + 'DB_TAG = os.environ["TAG"]\n',          # replaced by a computed value
    'def f():\n    DB_TAG = "Zq81-mnbv-2026"\n',        # not a module-level name
    'DB_TAG = "${DB_PASSWORD}"\n',                      # placeholder
    "this is not python (",
])
def test_imported_name_without_a_literal_value(module_text):
    source = "from settings import DB_TAG\ndb.connect(password=DB_TAG)\n"
    assert analyze(source, "app.py", {"settings.py": module_text}.get) == []


def test_imports_are_followed_only_with_a_reader_and_until_rebound():
    source = "from settings import DB_TAG\ndb.connect(password=DB_TAG)\n"
    assert analyze(source, "app.py") == []
    rebound = "from settings import DB_TAG\nDB_TAG = os.environ['T']\ndb.connect(password=DB_TAG)\n"
    assert analyze(rebound, "app.py", {"settings.py": SETTINGS}.get) == []


def test_ignore_marker_on_an_imported_literal(tmp_path):
    (tmp_path / "settings.py").write_text(SETTINGS.strip() + "  # IGNORE\n")
    (tmp_path / "app.py").write_text("from settings import DB_TAG\ndb.connect(password=DB_TAG)\n")
    report = scan(cwd=tmp_path)
    assert report.findings == [] and report.suppressed == 1
    assert [f.file for f in scan(cwd=tmp_path, opts=Options(suppress=False)).findings] == ["settings.py"]


def test_columns_count_characters_not_bytes():
    line = 'año, señal = 1, 2; tag = "Zq81-mnbv-2026"'               # 2 bytes more than characters
    [flow] = analyze(line + "\ndb.connect(password=tag)\n")
    assert flow.origin.col == line.index("Zq81")


def test_ignore_marker_hides_the_flow_and_audit_mode_shows_it():
    source = 'v = "audit-me-42x"  # IGNORE\ndb.connect(password=v)\n'
    report = scan_snippet(source)
    assert report.findings == [] and report.suppressed == 1
    [f] = scan_snippet(source, opts=Options(suppress=False)).findings
    assert f.rule == "credential-flow"


def test_labels_under_credential_keys_are_not_secrets():
    assert analyze('labels = {"password": "Enter your password", "private-key": "private key block"}') == []
    [flow] = analyze('h = {"Authorization": "Bearer q9X2-mixed-77"}')
    assert flow.origin.value == "Bearer q9X2-mixed-77"


def test_not_python_returns_nothing():
    assert analyze("const password = 'x'; connect(password)") == []


def test_flow_finding_enriches_the_rule_finding_of_the_same_literal():
    report = scan_snippet(kv("db_password", "Tr0ub4dor&3x") + "\nconn = psycopg2.connect(password=db_password)\n")
    [f] = report.findings
    assert f.rule == "hardcoded-credential" and f.confidence == "high"
    assert f.found_by == ["rules", "flow"]
    assert "passed as password= to connect() (line 2)" in f.why


# --------------------------------------------------------------------------- #
# Slice: the logic of a change without the rest of the file
# --------------------------------------------------------------------------- #
FILLER = (ROOT / "secretscan" / "detectors.py").read_text()   # ~250 unrelated lines


def _big_file(tag_line: str, use: str) -> tuple[str, int, int]:
    head = f"import psycopg2\n{tag_line}\n"
    tail = f"\n\ndef open_db():\n    return psycopg2.connect(host='db', password={use})\n"
    source = head + FILLER + tail
    lines = source.splitlines()
    return source, 2, len(lines)


def test_slice_brings_the_far_use_of_a_changed_literal():
    source, tag, use = _big_file('SESSION_TAG = "Zq81-mnbv"', "SESSION_TAG")
    picked = slice_lines(source, {tag})
    assert {tag, use, use - 1} <= picked and len(picked) < 10


def test_slice_brings_the_far_literal_of_a_changed_use():
    source, tag, use = _big_file('SESSION_TAG = "Zq81-mnbv"', "SESSION_TAG")
    assert {tag, use} <= slice_lines(source, {use})


def test_slice_is_a_small_fraction_of_the_file():
    source, tag, _ = _big_file('SESSION_TAG = "Zq81-mnbv"', "SESSION_TAG")
    lines = source.splitlines()
    picked = slice_lines(source, {tag})
    assert sum(len(lines[n - 1]) for n in picked) < len(source) / 20


def test_unparsable_source_has_no_python_slice():
    assert slice_lines("this is not python (", {1}) is None


def test_analysis_is_fast_on_a_large_file():
    source = "\n".join(f'v{i} = "value-{i:06d}"\ndb.connect(password=v{i})' for i in range(2000))
    start = time.perf_counter()
    assert len(analyze(source)) == 2000
    assert time.perf_counter() - start < 3


def test_lexical_slice_links_names_in_any_language():
    js = ['const tag = "Zq81-mnbv-js";', *["// filler"] * 50,
          'mysql.createConnection({host: "db", password: tag});']
    use = len(js)
    assert lexical_slice(js, {use}) == {1, use}           # the change uses tag: its literal comes along
    assert lexical_slice(js, {1}) == {1, use}             # the change assigns tag: its use comes along


def test_lexical_slice_is_bounded_per_name():
    lines = ['tag = "Zq81-mnbv"', *["send(tag)"] * 20]
    assert lexical_slice(lines, {1}) == {1, 2, 3, 4}
