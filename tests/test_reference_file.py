"""Acceptance criterion: the professor's file gives exactly the expected result, in
both formats it exists in (the original Word document and its transcription).

- reports valid_password (line 7), explained by its use: compared with getpass()
- does not report test_password, which carries the # IGNORE marker
- does not report valid_username
"""
import hashlib
import json

import pytest

from conftest import ROOT, run_cli
from secretscan.scanner import Options, scan, to_text

# Pinned so that nobody edits a reference file to make a test pass.
SHA256 = {
    "samples/app.py": "e41de8ebc6a52124d609f8e9c896e0b19d64522c8c9c0df0b7519975b6e5b08d",
    "samples/FicheroT2.docx": "8fbdb02439d74beb2ece64ecef9f9a206132fb15ec84960d2d8148be0a149d52",
}
FILES = ["samples/app.py", "samples/FicheroT2.docx"]


@pytest.mark.parametrize("path", FILES)
def test_reference_files_are_unchanged(path):
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == SHA256[path]


def test_word_document_holds_exactly_the_transcribed_program():
    text = to_text((ROOT / "samples/FicheroT2.docx").read_bytes(), "FicheroT2.docx")
    assert text.rstrip("\n") == (ROOT / "samples/app.py").read_text().rstrip("\n")


@pytest.mark.parametrize("path", FILES)
def test_exact_result(path):
    report = scan([path], cwd=ROOT)
    [f] = report.findings
    assert (f.file, f.line, f.column, f.key) == (path, 7, 23, "valid_password")
    assert f.rule == "hardcoded-credential" and f.confidence == "high"
    assert f.why == ["credential-like name receives a literal",
                     "compared with the password read by getpass() (line 13)"]
    assert f.found_by == ["rules", "flow"]
    assert report.suppressed == 1                       # testsecret, by its # IGNORE marker


@pytest.mark.parametrize("path", FILES)
def test_audit_mode_shows_the_ignored_line_too(path):
    report = scan([path], cwd=ROOT, opts=Options(suppress=False))
    assert [f.key for f in report.findings] == ["valid_password", "test_password"]


@pytest.mark.parametrize("path", FILES)
def test_cli_json_exit_1_and_no_value_in_clear(path):
    proc = run_cli(["scan", path, "--format", "json"], cwd=ROOT)
    assert proc.returncode == 1
    [finding] = json.loads(proc.stdout)["findings"]
    assert finding["secret"] == {"prefix": "se", "suffix": "23", "length": 17}
    assert "securepassword123" not in proc.stdout and "testsecret" not in proc.stdout
