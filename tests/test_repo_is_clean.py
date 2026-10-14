"""The repository passes its own scanner, except samples/ (dirty on purpose).

The tests build their secrets at runtime (conftest.kv), so the pre-commit hook
never blocks an ordinary commit of this project.
"""
from conftest import ROOT
from secretscan.scanner import Options, scan


def test_repository_is_clean_outside_samples():
    report = scan(cwd=ROOT, opts=Options(excludes=("samples",)))
    assert [f"{f.file}:{f.line} {f.rule}" for f in report.findings] == []
    assert report.files_scanned > 10
