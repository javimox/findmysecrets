"""The repository passes its own scanner, except generated/example content."""
from conftest import ROOT
from secretscan.scanner import Options, scan


def test_repository_is_clean_outside_samples():
    report = scan(cwd=ROOT, opts=Options(excludes=("samples", "*.egg-info")))
    assert [f"{f.file}:{f.line} {f.rule}" for f in report.findings] == []
    assert report.files_scanned > 10
