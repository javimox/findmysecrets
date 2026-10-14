"""Formats converted to text (notebooks; Word is in test_reference_file.py), encodings and size limits."""
import json
from pathlib import Path

from conftest import kv
from secretscan import scanner
from secretscan.scanner import Options, scan, to_text

PW = "Tr0ub4dor&" + "3x"


def notebook(*cells) -> bytes:
    return json.dumps({"cells": list(cells), "nbformat": 4}).encode()


def cell(kind, *lines, outputs=()):
    return {"cell_type": kind, "source": [line + "\n" for line in lines], "outputs": list(outputs)}


def test_notebook_becomes_a_python_file():
    text = to_text(notebook(
        cell("code", "%pip install psycopg2", "import psycopg2"),
        cell("markdown", "# Setup"),
        cell("code", "%%bash", "echo hi"),
        cell("code", "print(1)", outputs=[{"output_type": "stream", "text": ["1\n"]}]),
    ), "n.ipynb")
    assert text.splitlines() == ["# %pip install psycopg2", "import psycopg2", "# # Setup",
                                 "# %%bash", "# echo hi", "print(1)", "# 1"]


def test_secrets_in_notebooks_rules_flow_and_ignore(tmp_path):
    (tmp_path / "n.ipynb").write_bytes(notebook(
        cell("code", "!pip install psycopg2", 'tag = "Zq81-mnbv-nb"', "conn = psycopg2.connect(password=tag)"),
        cell("code", kv("api_key", PW), kv("db_password", PW) + "  # IGNORE"),
    ))
    report = scan(["n.ipynb"], cwd=tmp_path)
    assert [(f.line, f.rule) for f in report.findings] == [(2, "credential-flow"), (4, "hardcoded-credential")]
    assert report.suppressed == 1


def test_secret_printed_in_a_notebook_output(tmp_path):
    output = {"output_type": "execute_result", "data": {"text/plain": ["'postgresql://app:" + PW + "@db/x'"]}}
    (tmp_path / "n.ipynb").write_bytes(notebook(cell("code", "dsn", outputs=[output])))
    assert [f.rule for f in scan(["n.ipynb"], cwd=tmp_path).findings] == ["connection-string"]


def test_documents_that_cannot_be_converted_make_the_scan_incomplete(tmp_path):
    (tmp_path / "n.ipynb").write_text('{"cells": [42]}')
    (tmp_path / "w.docx").write_bytes(b"not a zip")
    report = scan(cwd=tmp_path)
    assert report.exit_code == 3 and report.files_skipped == 2
    assert sorted(m.split(":")[0] for m in report.incomplete) == ["n.ipynb", "w.docx"]


def test_excluded_directories_are_not_walked(tmp_path):
    (tmp_path / "images").mkdir()
    (tmp_path / "images" / "broken.docx").write_bytes(b"not a zip")
    (tmp_path / "images" / "logo.svg").write_text("<svg/>")
    report = scan(cwd=tmp_path, opts=Options(excludes=("images/*",)))
    assert report.incomplete == [] and report.excluded == 1 and report.dirs_skipped == 0   # one directory


def test_an_unreadable_file_makes_the_scan_incomplete(tmp_path, monkeypatch):
    (tmp_path / "locked.py").write_text("x = 1\n")
    real_open = Path.open

    def open_(self, *args, **kwargs):
        if self.name == "locked.py":
            raise PermissionError(13, "denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_)
    report = scan(cwd=tmp_path)
    assert report.exit_code == 3 and report.incomplete == ["locked.py: cannot be read (denied)"]


def test_utf16_text_is_decoded(tmp_path):
    (tmp_path / "w.ps1").write_bytes(("﻿" + kv("$db_password", PW, quote="'") + "\r\n").encode("utf-16-le"))
    assert [f.secret for f in scan(["w.ps1"], cwd=tmp_path).findings] == [PW]


def test_a_text_file_too_large_to_analyse_makes_the_scan_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 64)
    (tmp_path / "big.env").write_text("A=1\n" * 40)
    (tmp_path / "big.bin").write_bytes(b"\0" * 100)               # a large binary is out of scope
    report = scan(cwd=tmp_path)
    assert report.exit_code == 3 and report.files_skipped == 2
    assert [m.split(":")[0] for m in report.incomplete] == ["big.env"]


def test_a_staged_text_file_too_large_to_analyse_blocks_the_commit(repo, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 64)
    repo.write("dump.sql", *["INSERT INTO t VALUES (1);"] * 10)
    repo.git("add", "-A")
    assert scan(cwd=repo.path, mode="staged").exit_code == 3
