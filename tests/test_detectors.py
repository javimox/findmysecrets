"""Line rules, placeholders, entropy, the IGNORE marker, literals, redaction and ids."""
import random
import string
import time

import pytest

from conftest import kv, scan_snippet
from samples.make_fake_tokens import fake_pem, fake_tokens
from secretscan.detectors import (detect_line, ignore_marker, is_placeholder, is_secret_key,
                                  literals, looks_random)
from secretscan.scanner import Finding, redact


def rules(line: str, path: str = "app.py") -> list[str]:
    return [d.rule for d in detect_line(line, path)]


# --------------------------------------------------------------------------- #
# Provider formats (module book, p. 65), generated at runtime
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("expected, line", fake_tokens())
def test_provider_tokens(expected, line):
    assert rules(line) == [expected]


@pytest.mark.parametrize("seed", range(20))
def test_provider_tokens_with_other_seeds(seed):
    for expected, line in fake_tokens(seed):
        assert rules(line) == [expected]


def test_full_pem_block_is_one_finding():
    report = scan_snippet(fake_pem(), "deploy/id_rsa")
    assert [(f.rule, f.line) for f in report.findings] == [("private-key", 1)]


@pytest.mark.parametrize("header", ["OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY",
                                    "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"])
def test_private_key_variants(header):
    assert rules("-----BEGIN " + header + "-----") == ["private-key"]


def test_public_key_is_not_a_secret():
    assert rules("-----BEGIN " + "PUBLIC KEY-----") == []


def test_provider_rule_wins_inside_an_assignment():
    _, token = fake_tokens()[6]                          # stripe
    assert rules(kv("STRIPE_SECRET_KEY", token.split()[-1])) == ["stripe-key"]


# --------------------------------------------------------------------------- #
# Suspicious assignments across languages and formats
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("line, path", [
    (kv("db_password", "Tr0ub4dor&3"), "app.py"),                         # Python
    (kv("self.api_key", "k-9f8e7d6c"), "app.py"),                         # attribute
    (kv('"password"', "hunter2-x", sep=": "), "config.json"),             # JSON
    (kv("  client_secret", "abc-def-123", sep=": "), "config.yml"),       # quoted YAML
    (kv("const apiKey", "k-12345678"), "app.js"),                         # JavaScript
    (kv("String dbPassword", "Tr0ub4dor&3"), "App.java"),                 # Java
    (kv("password", "Tr0ub4dor&3", sep=" := "), "main.go"),               # Go
    (kv("'password'", "Tr0ub4dor&3", sep=" => ", quote="'"), "db.php"),   # PHP
    (kv("token: str", "tok-3f9a-77c1"), "settings.py"),                   # type annotation
    (kv("if password", "letmein2026", sep=" == "), "auth.py"),            # comparison
    (kv("ACCESSTOKEN", "abcd-efgh-1234"), "app.py"),                      # compound word
    (kv("DB_PASSWORD", "m4iler-2026", sep="=", quote=""), ".env"),        # unquoted .env
    (kv("spring.datasource.password", "S3cret-x", sep="=", quote=""), "app.properties"),
    (kv("  password", "hunter2-x", sep=": ", quote=""), "values.yaml"),   # unquoted YAML
    (kv('cfg["password"]', "hunter2-x"), "app.py"),                       # subscript
    (kv("config['password']", "hunter2-x", quote="'"), "app.js"),
])
def test_assignments_detected(line, path):
    assert rules(line, path) == ["hardcoded-credential"]


@pytest.mark.parametrize("line, path", [
    (kv("valid_username", "admin"), "app.py"),                  # name without a secret word
    (kv("tokenizer", "bert-base-uncased"), "app.py"),           # "token" as a substring
    (kv("findmysecrets", "secretscan.cli:main"), "pyproject.toml"),
    (kv("TOKEN_URL", "https://auth.acme.test/token"), "app.py"),
    (kv("SECRET_NAME", "prod/app/db"), "app.py"),
    (kv("password", "abc"), "app.py"),                          # too short
    (kv("DB_PASSWORD", "value", sep="=", quote=""), "app.py"),  # unquoted outside config files
    ("password = getpass.getpass(" + '"Password: ")', "app.py"),
    ("API_KEY = os.environ[" + '"API_KEY"]', "app.py"),
    (kv("sort_key", "name-asc-desc"), "app.py"),                # "key" without a qualifier
    (kv("PASSWORD_MISMATCH", "Passwords do not match"), "app.py"),           # a message, not a secret
    (kv('  "password"', "Contraseña incorrecta", sep=": "), "locales/es.json"),
])
def test_not_secret_assignments(line, path):
    assert rules(line, path) == []


@pytest.mark.parametrize("name, expected", [
    ("valid_password", True), ("DBPassword", True), ("x-api-key", True), ("APIKEY", True),
    ("clientSecret", True), ("mysqlpassword", True), ("private_key", True), ("pwd", True),
    ("valid_username", False), ("secretary", False), ("tokenizer", False), ("author", False),
    ("password_field", False), ("cache_key", False),
])
def test_secret_names(name, expected):
    assert is_secret_key(name) is expected


# --------------------------------------------------------------------------- #
# Placeholders and references (module book, p. 65)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", [
    "YOUR_API_KEY", "your-token-here", "<TOKEN>", "xxxxxxxx", "changeme", "CHANGE_ME",
    "example-key", "AKIAIOSFODNN7EXAMPLE", "${{ secrets.MY_TOKEN }}", "$CI_JOB_TOKEN",
    "${DB_PASSWORD}", "{{ vault_password }}", "%DB_PASS%", "!vault", "vault:secret/data/db",
    "arn:aws:secretsmanager:eu-west-1:1:secret:x", "********", "none", "aaaaaaaa", "dummy",
    "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCY" + "EXAMPLEKEY", "dummyApiKey123", "MyExampleToken42",   # docs, fixtures
])
def test_placeholders(value):
    assert is_placeholder(value)
    assert rules(kv("api_key", value)) == []


def test_a_real_password_is_not_a_placeholder():
    assert not is_placeholder("securepassword")


@pytest.mark.parametrize("scheme", ["postgresql", "mysql", "mongodb+srv", "redis", "amqp", "https"])
def test_connection_strings(scheme):
    line = "DSN = '" + scheme + "://app:" + "S3cr3t-Pw" + "@db.internal:5432/x'"
    [d] = detect_line(line)
    assert (d.rule, line[d.start:d.end]) == ("connection-string", "S3cr3t-Pw")


def test_urls_without_credentials_are_ignored():
    assert rules("URL = 'https://db.internal:5432/app'") == []
    assert rules("uses: actions/checkout@v4") == []
    assert rules("url = 'postgres://app:${DB_PASS}@db:5432/app'") == []


# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #
def _random_tokens(n: int, count: int, seed: int = 1) -> list[str]:
    rnd = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    tokens = []
    while len(tokens) < count:
        t = "".join(rnd.choice(alphabet) for _ in range(n))
        if any(c.islower() for c in t) and any(c.isupper() for c in t) and any(c.isdigit() for c in t):
            tokens.append(t)
    return tokens


@pytest.mark.parametrize("length, min_recall", [(20, 0.90), (32, 0.95), (40, 0.95)])
def test_entropy_detects_random_tokens(length, min_recall):
    tokens = _random_tokens(length, 500)
    assert sum(map(looks_random, tokens)) / len(tokens) >= min_recall


@pytest.mark.parametrize("value", [
    "9fceb02d0ae598e95dc970b74767f19372d61af8",                          # commit hash
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    "3f2b8c1e-4d5a-4b6c-9e7f-1a2b3c4d5e6f",                              # UUID
    "sha512WithRSAEncryption", "NotificationDispatcherService2",         # identifiers
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",    # alphabet
    "short1Aa",
])
def test_entropy_ignores_public_data_and_identifiers(value):
    assert not looks_random(value)


def test_integrity_hashes_are_public_data():
    sri = "sha512-" + _random_tokens(86, 1)[0] + "=="           # as in package-lock.json and yarn.lock
    assert rules('"integrity": "' + sri + '",', "package-lock.json") == []
    assert rules('"signature": "' + sri[7:] + '",', "package-lock.json") == ["high-entropy-string"]


def test_entropy_only_in_literals_or_config_values():
    token = _random_tokens(24, 1)[0]
    assert rules("sig = '" + token + "'") == ["high-entropy-string"]
    assert rules("# " + token) == []
    assert rules("SIG=" + token, ".env") == ["high-entropy-string"]


# --------------------------------------------------------------------------- #
# IGNORE marker: explicit, upper case, inside a comment
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("marker, path", [
    ("# IGNORE", "app.py"), ("#IGNORE", "app.py"), ("# IGNORE: test fixture", "app.py"),
    ("// IGNORE", "app.js"), ("-- IGNORE", "app.sql"), ("; IGNORE", "app.ini"),
    ("/* IGNORE */", "app.c"), ("<!-- IGNORE -->", "app.xml"),
])
def test_ignore_marker_in_comments(marker, path):
    report = scan_snippet(kv("password", "Tr0ub4dor&3") + "  " + marker, path)
    assert report.findings == [] and report.suppressed == 1


def test_in_python_only_a_real_comment_is_a_marker():
    inside_a_string = 'doc = """\n' + kv("password", "Tr0ub4dor&3") + '  # IGNORE\n"""\n'
    assert [f.line for f in scan_snippet(inside_a_string).findings] == [2]
    assert scan_snippet(inside_a_string, "notes.txt").findings == []            # other formats: by line


@pytest.mark.parametrize("line", [
    kv("password", "Tr0ub4dor&3") + "  # do not ignore this, rotate it",   # ordinary comment
    kv("password", "Tr0ub4dor&3") + "  // TODO: ignore later",
    kv("password", "Tr0ub4dor&3") + "  # ignore",                          # lower case
    kv("password", "Tr0ub4dor&3") + '; note = "# IGNORE"',                 # inside a string
    kv("password", "IGNORE-Tr0ub4dor"),                                    # inside the value
    kv("password", "Tr0ub4dor&3") + "  # IGNORED by mistake",              # another word
])
def test_ignore_marker_cannot_be_triggered_by_accident(line):
    assert not ignore_marker(line)
    assert len(scan_snippet(line).findings) == 1


# --------------------------------------------------------------------------- #
# Literals offered to the models
# --------------------------------------------------------------------------- #
def test_literals_on_a_line():
    line = 'conn = db.connect("db.internal", "app", "S3cr3t-pw-11")'
    assert [line[s:e] for s, e in literals(line)] == ["db.internal", "S3cr3t-pw-11"]  # "app" is too short


def test_literals_include_unquoted_config_values_and_skip_placeholders():
    assert [s for s in literals("DB_TAG=Zq81-mnbv", ".env")] == [(7, 16)]
    assert literals('key = "${API_KEY}"') == []


# --------------------------------------------------------------------------- #
# Redaction and stable ids
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("secret, expected", [
    ("securepassword123", {"prefix": "se", "suffix": "23", "length": 17}),
    ("abcde", {"prefix": "", "suffix": "", "length": 5}),
    ("A" * 40, {"prefix": "AAAA", "suffix": "AAAA", "length": 40}),
])
def test_redaction(secret, expected):
    assert redact(secret) == expected


def test_redaction_never_shows_more_than_a_third():
    for n in range(1, 120):
        r = redact("x" * n)
        assert len(r["prefix"]) + len(r["suffix"]) <= n / 3


def test_id_does_not_depend_on_the_line_number():
    line = kv("password", "Tr0ub4dor&3")
    a = scan_snippet(line).findings[0]
    b = scan_snippet("\n\n\n" + line).findings[0]
    assert a.line != b.line and a.id == b.id


def test_id_depends_on_file_and_value():
    one, two = "value-" + "1", "value-" + "2"
    a = Finding("hardcoded-credential", "a.py", 1, 1, one)
    assert a.id != Finding("hardcoded-credential", "b.py", 1, 1, one).id
    assert a.id != Finding("hardcoded-credential", "a.py", 1, 1, two).id


def test_secret_is_not_in_repr_or_dict():
    f = scan_snippet(kv("password", "Tr0ub4dor&3")).findings[0]
    assert f.secret not in repr(f)
    assert f.secret not in str(f.to_dict())


def test_an_escaped_quote_stays_inside_the_value():
    line = kv("password", 'abc\\"def123')
    [d] = detect_line(line)
    assert line[d.start:d.end] == 'abc\\"def123'


def test_backslashes_without_a_closing_quote_take_linear_time():
    for n in (36, 20_000):       # a backtracking pattern needs seconds at 36 backslashes, days at 60
        start = time.perf_counter()
        rules(kv("password", "\\" * n)[:-1])
        literals(kv("password", "\\" * n)[:-1])               # the literal list the models receive
        assert time.perf_counter() - start < 1
