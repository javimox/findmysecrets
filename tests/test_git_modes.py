"""Staged (pre-commit), history and push modes on throwaway repositories."""
import json
import shutil

import pytest

from conftest import ROOT, kv
from samples.make_fake_tokens import fake_tokens
from secretscan.scanner import Options, ScanError, iter_added_lines, pushed_revs, scan, scan_history

PW_1 = "Tr0ub4dor&" + "3x"
PW_2 = "C0rrect-H0rse-" + "9"


def staged(repo, **kw):
    return scan(cwd=repo.path, mode="staged", **kw)


def test_staged_reads_only_what_is_staged(repo):
    repo.write("app.py", "import os", "print('hi')")
    repo.commit("start")
    repo.write("app.py", "import os", kv("db_password", PW_1), "print('hi')")
    repo.git("add", "app.py")
    repo.write("other.py", kv("api_key", PW_2))            # not staged: does not count
    report = staged(repo)
    assert [(f.file, f.line, f.key) for f in report.findings] == [("app.py", 2, "db_password")]
    assert report.files_scanned == 1


def test_staged_content_wins_over_the_working_tree(repo):
    repo.write("app.py", kv("db_password", PW_1))
    repo.git("add", "app.py")
    repo.write("app.py", "db_password = os.environ['P']")    # unstaged fix: the commit still leaks
    assert [f.secret for f in staged(repo).findings] == [PW_1]


def test_staged_in_a_repository_without_commits(repo):
    repo.write("config.py", kv("secret", PW_1))
    repo.git("add", "config.py")
    assert [f.file for f in staged(repo).findings] == ["config.py"]


def test_removing_a_secret_is_not_reported(repo):
    repo.write("app.py", kv("password", PW_1))
    repo.commit("with secret")
    repo.write("app.py", "password = os.environ['PASSWORD']")
    repo.git("add", "app.py")
    assert staged(repo).findings == []


def test_old_secret_in_an_untouched_line_is_not_reblocked(repo):
    repo.write("app.py", kv("password", PW_1), "db.connect(password=password)")
    repo.commit("old secret")
    repo.write("app.py", kv("password", PW_1), "db.connect(password=password)", "print('unrelated')")
    repo.git("add", "app.py")
    assert staged(repo).findings == []


def test_new_use_of_an_existing_literal_is_reported(repo):
    """Scenario B: the diff holds no literal at all; the slice finds it 60 lines up."""
    repo.write("app.py", 'session_tag = "Zq81-mnbv-26"', *["pass"] * 60,
               "db.connect(password=os.environ['P'])")
    repo.commit("base")
    repo.write("app.py", 'session_tag = "Zq81-mnbv-26"', *["pass"] * 60,
               "db.connect(password=session_tag)")
    repo.git("add", "app.py")
    [f] = staged(repo).findings
    assert (f.rule, f.line, f.secret) == ("credential-flow", 1, "Zq81-mnbv-26")
    assert f.why == ["passed as password= to connect() (line 62)"]


def test_new_literal_with_a_far_unchanged_use_is_reported(repo):
    """Scenario A: the use is 60 lines below and does not change."""
    repo.write("app.py", "session_tag = load_tag()", *["pass"] * 60, "db.connect(password=session_tag)")
    repo.commit("base")
    repo.write("app.py", 'session_tag = "Zq81-mnbv-26"', *["pass"] * 60, "db.connect(password=session_tag)")
    repo.git("add", "app.py")
    assert [(f.rule, f.line) for f in staged(repo).findings] == [("credential-flow", 1)]


def test_reformatting_the_use_reports_nothing(repo):
    repo.write("app.py", 'tag = "Zq81-mnbv-26"', "db.connect(password=tag)")
    repo.commit("base")
    repo.write("app.py", 'tag = "Zq81-mnbv-26"', "db.connect( password = tag )")
    repo.git("add", "app.py")
    assert staged(repo).findings == []


def test_a_new_link_through_an_unchanged_literal_and_use_is_reported(repo):
    """Scenario C: neither the literal nor its use changes; an assignment in between does."""
    repo.write("app.py", 'tag = "Zq81-mnbv-26"', "pw = os.environ['P']", "db.connect(password=pw)")
    repo.commit("base")
    repo.write("app.py", 'tag = "Zq81-mnbv-26"', "pw = tag", "db.connect(password=pw)")
    repo.git("add", "app.py")
    assert [(f.rule, f.line) for f in staged(repo).findings] == [("credential-flow", 1)]


# --------------------------------------------------------------------------- #
# Across files: a literal in settings.py, its use in app.py
# --------------------------------------------------------------------------- #
def test_new_use_of_a_literal_from_another_module(repo):
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"')
    repo.write("app.py", "from settings import DB_TAG", "print(DB_TAG)")
    repo.commit("base")
    repo.write("app.py", "from settings import DB_TAG", "db.connect(password=DB_TAG)")
    repo.git("add", "app.py")
    [f] = staged(repo).findings
    assert (f.file, f.line, f.column, f.why) == ("settings.py", 1, 11, ["passed as password= to connect() (app.py:2)"])


def test_new_literal_in_a_module_used_by_an_unchanged_file(repo):
    repo.write("settings.py", "DB_TAG = os.environ['TAG']")
    repo.write("app.py", "import settings", "db.connect(password=settings.DB_TAG)")
    repo.commit("base")
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"')
    repo.git("add", "settings.py")
    repo.write("settings.py", "DB_TAG = os.environ['TAG']")          # unstaged fix: the commit still leaks
    assert [(f.file, f.line) for f in staged(repo).findings] == [("settings.py", 1)]


def test_importers_are_read_only_when_a_module_literal_changes(repo):
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"', "def retries():", "    return 1")
    repo.write("app.py", "from settings import DB_TAG", "print(DB_TAG)")
    repo.commit("base")
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"', "def retries():", "    return 2")
    repo.git("add", "-A")
    assert staged(repo).files_scanned == 1                             # app.py cannot receive anything new


def test_an_existing_flow_in_an_importer_is_not_new(repo):
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"')
    repo.write("old.py", "from settings import DB_TAG", "db.connect(password=DB_TAG)")
    repo.commit("base")
    repo.write("settings.py", 'DB_TAG = "Zq81-mnbv-26"', 'GREETING = "hello there"')
    repo.git("mv", "old.py", "new.py")                                 # the importer moves too
    repo.git("add", "-A")
    report = staged(repo)
    assert report.findings == [] and report.files_scanned == 2


def test_pure_rename_reports_nothing(repo):
    repo.write("old.py", kv("db_password", PW_1))
    repo.commit("base")
    repo.git("mv", "old.py", "new.py")
    assert staged(repo).findings == []


def test_rename_with_changes_reports_only_the_changes(repo):
    repo.write("old.py", kv("db_password", PW_1), *["x = 1"] * 10)
    repo.commit("base")
    repo.git("mv", "old.py", "new.py")
    repo.write("new.py", kv("db_password", PW_1), *["x = 1"] * 10, kv("api_key", PW_2))
    repo.git("add", "new.py")
    assert [(f.file, f.line) for f in staged(repo).findings] == [("new.py", 12)]


def test_staged_word_document_is_scanned_whole(repo):
    shutil.copy(ROOT / "samples" / "FicheroT2.docx", repo.path / "FicheroT2.docx")
    repo.git("add", "FicheroT2.docx")
    assert [(f.file, f.line) for f in staged(repo).findings] == [("FicheroT2.docx", 7)]


def test_staged_ignore_and_exclusions(repo):
    repo.write("app.py", kv("password", PW_1) + "  # IGNORE")
    repo.write("samples/demo.py", kv("password", PW_2))
    repo.git("add", "-A")
    report = staged(repo, opts=Options(excludes=("samples",)))
    assert report.findings == [] and report.suppressed == 1 and report.excluded == 1


def test_git_config_exclusions_scope_commits_not_audits(repo):
    repo.write("my samples/demo.py", kv("password", PW_2))
    repo.git("add", "-A")
    repo.git("config", "--add", "findmysecrets.exclude", "my samples/*")    # a pattern may hold spaces
    assert staged(repo).findings == []
    repo.commit("samples")
    assert scan_history(repo.path).findings == []
    assert [f.file for f in scan(cwd=repo.path).findings] == ["my samples/demo.py"]


@pytest.mark.parametrize("name", ["my dir/app.py", 'we"ird.py', 'a b"c.py', "año.py", "back\\slash.py"])
def test_any_file_name_is_scanned_in_commits(repo, name):
    """git ends names holding a space with a tab, and C-quotes names with quotes or backslashes."""
    repo.write(name, kv("db_password", PW_1))
    repo.git("add", "-A")
    assert [f.file for f in staged(repo).findings] == [name]
    repo.commit("odd name")
    assert [f.file for f in scan_history(repo.path).findings] == [name]


def test_allow_file_counts_once_it_is_staged(repo):
    repo.write("app.py", kv("password", PW_1))
    repo.git("add", "app.py")
    [f] = staged(repo).findings
    repo.write(".secretscan-allow", f"{f.id}  # test fixture")
    assert [x.id for x in staged(repo).findings] == [f.id]             # the commit does not carry it yet
    repo.git("add", ".secretscan-allow")
    report = staged(repo)
    assert report.findings == [] and report.suppressed == 1
    assert [x.id for x in staged(repo, opts=Options(suppress=False)).findings] == [f.id]


def test_outside_a_repository_staged_is_an_error(tmp_path, isolated_git, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    with pytest.raises(ScanError):
        scan(cwd=tmp_path, mode="staged")


# --------------------------------------------------------------------------- #
# History: Git never forgets
# --------------------------------------------------------------------------- #
def test_history_finds_secrets_already_deleted(repo):
    repo.write("app.py", kv("password", PW_1))
    leak = repo.commit("with secret")
    repo.write("app.py", "password = os.environ['PASSWORD']")
    repo.commit("fixed")
    assert scan(cwd=repo.path).findings == []                 # the working tree is clean...
    report = scan_history(repo.path)                          # ...the history is not
    assert [(f.commit, f.file, f.line) for f in report.findings] == [(leak, "app.py", 1)]
    assert report.commits_scanned == 2


def test_history_with_range(repo):
    repo.write("a.py", kv("password", PW_1))
    first = repo.commit("one")
    repo.write("b.py", kv("password", PW_2))
    second = repo.commit("two")
    report = scan_history(repo.path, [f"{first}..{second}"])
    assert [(f.commit, f.file) for f in report.findings] == [(second, "b.py")]


def test_history_converts_word_documents_and_notebooks(repo):
    """Their diff is binary or JSON: each version is converted and compared with the one before."""
    shutil.copy(ROOT / "samples" / "FicheroT2.docx", repo.path)
    shutil.copy(ROOT / "samples" / "notebook.ipynb", repo.path)
    repo.git("add", "-A")
    from_index = [f.id for f in staged(repo).findings if f.file == "FicheroT2.docx"]
    first = repo.commit("documents")
    report = scan_history(repo.path)
    assert [(f.file, f.line) for f in report.findings] == [("FicheroT2.docx", 7), ("notebook.ipynb", 11)]
    assert report.suppressed == 1                                   # test_password  # IGNORE
    assert from_index == [report.findings[0].id]                    # one allow-list entry serves both hooks

    notebook = json.loads((repo.path / "notebook.ipynb").read_text())
    token = fake_tokens()[2][1].split()[-1]                         # GitHub format
    cell = [kv("api_key", PW_1) + "\n", kv("fixture", token) + "  # IGNORE"]   # in JSON, IGNORE is inside a string
    notebook["cells"].append({"cell_type": "code", "source": cell, "outputs": []})
    (repo.path / "notebook.ipynb").unlink()
    (repo.path / "weekly report.ipynb").write_text(json.dumps(notebook, indent=1))    # renamed and edited
    second = repo.commit("one more cell")
    assert "R0" in repo.git("show", "--name-status", "--format=", second)
    report = scan_history(repo.path, [f"{first}..{second}"])
    assert [(f.commit, f.file, f.secret) for f in report.findings] == [(second, "weekly report.ipynb", PW_1)]
    assert report.suppressed == 1


def test_a_push_checks_only_the_commits_the_remote_lacks(tmp_path):
    zero, tip, theirs = "0" * 40, "a" * 40, "b" * 40
    deletion = f"refs/heads/old {zero} refs/heads/old {theirs}\n"
    assert pushed_revs(f"refs/heads/main {tip} refs/heads/main {theirs}\n{deletion}", "origin") == [
        tip, "--not", "--remotes=origin"]
    assert pushed_revs(deletion, "origin") == []
    assert scan_history(tmp_path, [], mode="push").exit_code == 0


def test_history_range_rejects_dangerous_options(repo):
    with pytest.raises(ScanError):
        scan_history(repo.path, ["HEAD", "--output=/tmp/pwned"])


def test_same_id_in_every_mode_and_from_a_subdirectory(repo):
    repo.write("src/app.py", "x = 1", kv("password", PW_1))
    repo.git("add", "-A")
    from_index = staged(repo).findings
    repo.commit("one")
    from_history = scan_history(repo.path).findings
    from_files = scan(["app.py"], cwd=repo.path / "src").findings
    assert from_files[0].file == "src/app.py"
    assert from_index[0].id == from_history[0].id == from_files[0].id


def test_diff_parser_does_not_confuse_content_with_headers():
    diff = "\n".join(["diff --git a/f.sql b/f.sql", "--- a/f.sql", "+++ b/f.sql", "@@ -1,2 +1,2 @@",
                      "--- deleted SQL comment", "+++ added content", " context", "+another"])
    assert list(iter_added_lines(diff)) == [(None, "f.sql", 1, "++ added content"), (None, "f.sql", 3, "another")]


def test_more_uses_of_an_existing_secret_upload_nothing_new(repo):
    """The hook stops what a commit uploads. Using an existing literal once more, or through a
    renamed import, uploads no new secret: the audit (`findmysecrets scan`) reports it."""
    repo.write("app.py", "import psycopg2", kv("tag", PW_1), "psycopg2.connect(password=tag)")
    repo.commit("base")
    repo.write("app.py", "import psycopg2 as pg", kv("tag", PW_1), "pg.connect(password=tag)",
               "pg.connect(password=tag)")
    repo.git("add", "app.py")
    assert staged(repo).findings == []


def test_push_ignores_an_uncommitted_allow_entry(repo):
    repo.write("app.py", kv("db_password", PW_1))
    tip = repo.commit("leak")
    [finding] = scan_history(repo.path, [tip], mode="push").findings

    repo.write(".secretscan-allow", f"{finding.id}  # local only")
    report = scan_history(repo.path, [tip], mode="push")
    assert [f.id for f in report.findings] == [finding.id]

    allowed_tip = repo.commit("review false positive")
    report = scan_history(repo.path, [allowed_tip], mode="push")
    assert report.findings == [] and report.suppressed == 1
