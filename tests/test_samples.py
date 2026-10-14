"""Every sample reports exactly what its comments announce.

"expected: <rule>" lines must give that finding and no other line may give one.
"candidate" lines must not be reported without AI, but must reach the models as
data-flow candidates. The reference file has its own test (test_reference_file.py).
"""
import re

import pytest

from conftest import ROOT
from samples.make_fake_tokens import main as make_fake_tokens
from secretscan.flow import analyze
from secretscan.scanner import scan, to_text

EXPECTED_RE = re.compile(r"expected: ([a-z-]+)")
SAMPLES = sorted(p for p in (ROOT / "samples").iterdir()
                 if p.is_file() and p.suffix in {".py", ".yml", ".env"} and p.name not in {"app.py", "make_fake_tokens.py"})


def marked(path, pattern, text=None):
    text = path.read_text() if text is None else text
    return {(n, m.group(1) if m.groups() else "") for n, line in enumerate(text.splitlines(), 1)
            if (m := re.search(pattern, line))}


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_sample(path):
    rel = path.relative_to(ROOT).as_posix()
    found = {(f.line, f.rule) for f in scan([rel], cwd=ROOT).findings}
    assert found == marked(path, EXPECTED_RE)


def test_cross_file_sample():
    """The literal is in settings.py; only app.py, which imports it, shows it is a password."""
    found = {(f.file, f.line, f.rule) for f in scan(["samples/crossfile"], cwd=ROOT).findings}
    settings = ROOT / "samples" / "crossfile" / "settings.py"
    assert found == {("samples/crossfile/settings.py", n, r) for n, r in marked(settings, EXPECTED_RE)}


def test_notebook_sample():
    path = ROOT / "samples" / "notebook.ipynb"
    found = {(f.line, f.rule) for f in scan(["samples/notebook.ipynb"], cwd=ROOT).findings}
    assert found == marked(path, EXPECTED_RE, to_text(path.read_bytes(), path.name))


def test_flow_candidates_reach_the_models():
    path = ROOT / "samples" / "flow_cases.py"
    candidates = {f.origin.line for f in analyze(path.read_text()) if not f.strong}
    assert candidates == {n for n, _ in marked(path, r"# candidate$")}


def test_every_rule_family_has_cases():
    rules = set().union(*({r for _, r in marked(p, EXPECTED_RE)} for p in SAMPLES))
    assert rules == {"hardcoded-credential", "connection-string", "high-entropy-string", "credential-flow"}


def test_negative_cases_report_nothing():
    assert scan(["samples/negative_cases.py"], cwd=ROOT).findings == []


def test_ignore_marker_in_env_file():
    assert scan(["samples/app.env"], cwd=ROOT).suppressed == 1


def test_generated_provider_tokens():
    make_fake_tokens()
    report = scan(["samples/generated"], cwd=ROOT)
    assert sorted({f.rule for f in report.findings}) == [
        "aws-access-key-id", "github-token", "private-key", "slack-token", "stripe-key"]
    assert len(report.findings) == 9
