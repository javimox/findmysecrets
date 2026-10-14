"""Command line: formats, options, exit codes and the Git hooks."""
import json
import os
import subprocess
import sys
import time

import pytest

from conftest import ROOT, kv, run_cli
from secretscan.cli import install_hooks, main, to_text
from secretscan.scanner import Finding, Report, ScanError

PW = "Tr0ub4dor&" + "3x"


def run(args, capsys):
    code = main(args)
    return code, capsys.readouterr()


def test_clean_exits_0(tmp_path, monkeypatch, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    monkeypatch.chdir(tmp_path)
    code, out = run(["scan", "--format", "json"], capsys)
    assert code == 0 and json.loads(out.out)["findings"] == []


def test_findings_exit_1_with_why_and_redaction(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(kv("password", PW) + "\n")
    monkeypatch.chdir(tmp_path)
    code, out = run(["scan"], capsys)
    assert code == 1
    assert "app.py:1:13  hardcoded-credential [medium]" in out.out
    assert "why: credential-like name receives a literal" in out.out
    assert PW not in out.out


def test_json_carries_why_and_found_by(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text('v = "weird-value-11"\ndb.connect(password=v)\n')
    monkeypatch.chdir(tmp_path)
    _, out = run(["scan", "--format", "json"], capsys)
    [f] = json.loads(out.out)["findings"]
    assert f["found_by"] == ["flow"] and f["why"] == ["passed as password= to connect() (line 2)"]


def test_missing_path_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["scan", "missing"], capsys)
    assert code == 2 and "does not exist" in out.err


@pytest.mark.parametrize("args", [["scan", "--staged", "--history"], ["scan", "--staged", "--range", "a..b"],
                                  ["scan", "--staged", "src"], ["scan", "--history", "--ai", "triage"],
                                  ["scan", "--pushed", "origin", "src"], ["scan", "--pushed", "origin", "--staged"],
                                  ["scan", "--threshold", "2"], ["scan", "--chat-url", "file:///etc"]])
def test_invalid_combinations_exit_2(args):
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 2


def test_min_confidence_filters(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(kv("password", PW) + "\n")
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "--min-confidence", "high"], capsys)[0] == 0


def test_exclude(tmp_path, monkeypatch, capsys):
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "app.py").write_text(kv("password", PW) + "\n")
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "--exclude", "samples/"], capsys)[0] == 0
    assert run(["scan", "--exclude", "*.py"], capsys)[0] == 0
    assert run(["scan", "--exclude", "other/*"], capsys)[0] == 1


def test_hidden_files_are_scanned_and_dependencies_are_skipped(tmp_path, monkeypatch, capsys):
    (tmp_path / ".env").write_text(kv("DB_PASSWORD", PW, sep="=", quote="") + "\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(kv("password", PW) + "\n")
    monkeypatch.chdir(tmp_path)
    _, out = run(["scan", "--format", "json"], capsys)
    report = json.loads(out.out)
    assert [f["file"] for f in report["findings"]] == [".env"] and report["summary"]["dirs_skipped"] == 1


def test_symlinks_are_not_followed_out_of_the_tree(tmp_path, monkeypatch, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(kv("password", PW) + "\n")
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "link.py").symlink_to(outside / "secret.py")
    (inside / "linkdir").symlink_to(outside)
    monkeypatch.chdir(inside)
    assert run(["scan"], capsys)[0] == 0


def test_text_output_cannot_be_rewritten_by_file_names_or_reasons():
    report = Report("files")
    report.add(Finding("hardcoded-credential", "evil\n0 finding(s)\x1b[2K.py", 1, 1, PW, key="k",
                       why=["reason\x1b[31m\nINCOMPLETE: none"]))
    out = to_text(report)
    assert "\x1b" not in out and "\n0 finding(s)" not in out and "\nINCOMPLETE: none" not in out
    assert out.startswith("evil?0 finding(s)?[2K.py:1:1")


def test_large_generated_file_is_fast(tmp_path, monkeypatch, capsys):
    (tmp_path / "bundle.js").write_text("\n".join(f'const v{i} = "value-{i:06d}";' for i in range(4000)))
    monkeypatch.chdir(tmp_path)
    start = time.perf_counter()
    assert run(["scan"], capsys)[0] == 0
    assert time.perf_counter() - start < 2


def test_python_m_secretscan_runs_without_installing():
    proc = run_cli(["--version"], cwd=ROOT)
    assert proc.returncode == 0 and "findmysecrets" in proc.stdout


# --------------------------------------------------------------------------- #
# Git hooks
# --------------------------------------------------------------------------- #
def test_hook_blocks_a_staged_secret_and_explains_why(repo):
    hooks = install_hooks(repo.path)
    assert [h.name for h in hooks] == ["pre-commit", "pre-push"]
    assert all(sys.executable in h.read_text() and os.access(h, os.X_OK) for h in hooks)
    repo.write("app.py", kv("db_password", PW))
    repo.git("add", "app.py")
    proc = run_cli(["scan", "--staged", "--ai", "off"], cwd=repo.path)
    assert proc.returncode == 1 and "Commit blocked: remove the secret" in proc.stdout


def test_real_git_commit_goes_through_the_hook(repo, monkeypatch):
    """`git commit` runs the installed hook: blocked with a secret, allowed once marked IGNORE."""
    install_hooks(repo.path)
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setenv("SECRETSCAN_AI", "off")
    repo.write("app.py", kv("db_password", PW))
    repo.git("add", "app.py")
    with pytest.raises(subprocess.CalledProcessError) as blocked:
        repo.git("commit", "-q", "-m", "leak")
    assert "Commit blocked" in blocked.value.stderr  # git shows hook output on stderr
    repo.write("app.py", kv("db_password", PW) + "  # IGNORE")
    repo.git("add", "app.py")
    repo.git("commit", "-q", "-m", "fixture marked as false positive")
    assert repo.git("log", "--format=%s") == "fixture marked as false positive"


def test_hook_without_models_fails_closed(repo):
    repo.write("app.py", 'conn = db.connect("db.internal", "app", "S3cr3t-pw-11")')
    repo.git("add", "app.py")
    proc = run_cli(["scan", "--staged", "--ai", "triage", "--timeout", "2"], cwd=repo.path,
                   env={"SECRETSCAN_DECISION_URL": "http://127.0.0.1:9/v1"})
    assert proc.returncode == 3 and "analysis is incomplete" in proc.stdout


def test_real_git_push_goes_through_the_hook(repo, tmp_path_factory, monkeypatch):
    """A commit that skipped the pre-commit hook (--no-verify) is stopped at `git push`;
    commits the remote already holds are not checked again."""
    remote = tmp_path_factory.mktemp("remote")
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    repo.git("remote", "add", "origin", str(remote))
    install_hooks(repo.path)
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setenv("SECRETSCAN_AI", "triage")          # the push hook runs rules only, whatever this says

    def push():
        return subprocess.run(["git", "push", "-q", "origin", "main"], cwd=repo.path, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)

    repo.write("app.py", "print('hi')")
    repo.git("add", "app.py")
    repo.git("commit", "-q", "--no-verify", "-m", "clean")
    assert "0 finding(s) in 1 file(s) of 1 commit(s)" in push().stdout
    repo.write("app.py", kv("db_password", PW))
    repo.git("add", "app.py")
    repo.git("commit", "-q", "--no-verify", "-m", "leak")
    blocked = push()
    assert blocked.returncode and "Push blocked" in blocked.stdout and PW not in blocked.stdout
    assert repo.git("ls-remote", "origin", "main").split()[0] == repo.git("rev-parse", "HEAD~1")
    repo.git("reset", "-q", "--hard", "HEAD~1")                   # the commit is dropped before anyone sees it
    repo.write("app.py", "import os", "db_password = os.environ['DB_PASSWORD']")
    repo.git("add", "app.py")
    repo.git("commit", "-q", "--no-verify", "-m", "from the environment")
    accepted = push()
    assert accepted.returncode == 0 and "of 1 commit(s)" in accepted.stdout


def test_hooks_never_overwrite_a_foreign_hook(repo):
    pre_commit, pre_push = install_hooks(repo.path)
    pre_commit.unlink()
    pre_push.write_text("#!/bin/sh\necho someone else\n")
    with pytest.raises(ScanError):
        install_hooks(repo.path)
    assert not pre_commit.exists()                                # none is written


def test_install_hook_reports_disabled_hooks(repo, monkeypatch, capsys):
    repo.git("config", "core.hooksPath", "/dev/null")
    monkeypatch.chdir(repo.path)
    code, out = run(["install-hook"], capsys)
    assert code == 2 and "cannot write" in out.err


# --------------------------------------------------------------------------- #
# False positives without a comment: findmysecrets allow <id>
# --------------------------------------------------------------------------- #
def test_allow_marks_a_false_positive_by_id(repo, monkeypatch, capsys):
    repo.write("conf/data.json", "{" + kv('"api_token"', PW, sep=": ") + "}")    # JSON has no comments
    monkeypatch.chdir(repo.path / "conf")
    _, out = run(["scan", "--format", "json"], capsys)
    [f] = json.loads(out.out)["findings"]
    assert run(["allow", f["id"], "test fixture\x1b[2K"], capsys)[0] == 0
    assert run(["allow", f["id"]], capsys)[0] == 0                                # listed once
    assert (repo.path / ".secretscan-allow").read_text() == f"{f['id']}  # test fixture [2K\n"
    code, out = run(["scan"], capsys)
    assert code == 0 and "0 finding(s) in 1 file(s); 1 suppressed" in out.out
    assert run(["scan", "--show-suppressed"], capsys)[0] == 1


def test_allow_rejects_anything_but_an_id(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["allow", "../../etc"], capsys)
    assert code == 2 and "12-character finding id" in out.err and not (tmp_path / ".secretscan-allow").exists()


def test_each_model_is_configured_by_its_role(tmp_path, monkeypatch, capsys, ollama):
    """Decision and chat model: own URL (both ending in /v1) and own model, set as the hook sees them."""
    server = ollama(decide=lambda body: {q: 0.9 for q in body["questions"]})
    (tmp_path / "a.py").write_text('cfg_a = "q9-mixed-77zz"\n')
    monkeypatch.chdir(tmp_path)
    for name, value in {"SECRETSCAN_DECISION_URL": server.url + "/v1", "SECRETSCAN_DECISION_MODEL": "my-decider",
                        "SECRETSCAN_CHAT_URL": server.url + "/v1", "SECRETSCAN_CHAT_MODEL": "my-chat"}.items():
        monkeypatch.setenv(name, value)
    assert run(["scan", "--ai", "triage"], capsys)[0] == 0
    assert [(path, body["model"]) for path, body in server.requests] == [
        ("/v1/systemone", "my-decider"), ("/v1/chat/completions", "my-chat")]
