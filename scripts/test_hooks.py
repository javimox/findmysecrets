#!/usr/bin/env python3
"""Exercise the Git hooks and refresh docs/evidence/hook_offline.txt.

Runs entirely offline in a temporary repository and local bare remote.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "evidence" / "hook_offline.txt"


def env(*, ai: str | None = None) -> dict[str, str]:
    result = {k: v for k, v in os.environ.items() if not k.startswith("SECRETSCAN_")}
    result.update(
        {
            "PYTHONPATH": str(ROOT),
            "NO_COLOR": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "FindMySecrets Evidence",
            "GIT_AUTHOR_EMAIL": "evidence@example.invalid",
            "GIT_COMMITTER_NAME": "FindMySecrets Evidence",
            "GIT_COMMITTER_EMAIL": "evidence@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        }
    )
    if ai is not None:
        result["SECRETSCAN_AI"] = ai
    return result


def run(
    args: list[str],
    cwd: Path,
    *,
    run_env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=run_env or env(),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = run(["git", *args], cwd)
    if check and proc.returncode:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return proc


def tool(cwd: Path, *args: str, run_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return run([sys.executable, "-m", "secretscan", *args], cwd, run_env=run_env)


def normalize(text: str, repo: Path, remote: Path) -> str:
    text = text.replace(str(repo), "<repo>").replace(str(remote), "<server>")
    text = re.sub(r"(?m)^To /[^\n]+$", "To <server>", text)
    return text.rstrip()


def record(
    lines: list[str],
    command: str,
    proc: subprocess.CompletedProcess[str],
    repo: Path,
    remote: Path,
) -> None:
    lines.append(f"$ {command}")
    output = normalize(proc.stdout + proc.stderr, repo, remote)
    if output:
        lines.append(output)
    lines += [f"[exit code {proc.returncode}]", ""]


def sample_assignment(
    name_parts: tuple[str, ...],
    value_parts: tuple[str, ...],
    *,
    ignore: bool = False,
) -> str:
    """Build synthetic vulnerable source without embedding that source verbatim in this repository."""
    suffix = "  # IGNORE" if ignore else ""
    return f'{"".join(name_parts)} = "{"".join(value_parts)}"{suffix}\n'


def prepare_repo(base: Path) -> tuple[Path, Path]:
    repo = base / "repo"
    remote = base / "remote.git"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "initial.py").write_text('print("clean")\n', encoding="utf-8")
    git(repo, "add", "initial.py")
    git(repo, "commit", "-qm", "initial")
    return repo, remote


def test_pre_commit(lines: list[str], repo: Path, remote: Path) -> None:
    proc = tool(repo, "install-hook")
    record(lines, "findmysecrets install-hook", proc, repo, remote)

    # A staged secret must be blocked by pre-commit.
    (repo / "secret.py").write_text(
        sample_assignment(("pass", "word"), ("Super", "Secret", "-2026!")), encoding="utf-8"
    )
    git(repo, "add", "secret.py")
    proc = run(["git", "commit", "-m", "add secret"], repo, run_env=env())
    record(lines, "git commit -m 'add secret'", proc, repo, remote)
    git(repo, "reset", "-q")
    (repo / "secret.py").unlink()

    # An unstaged secret must not affect a clean staged commit.
    (repo / "tracked.py").write_text('print("clean")\n', encoding="utf-8")
    git(repo, "add", "tracked.py")
    git(repo, "commit", "--no-verify", "-qm", "add tracked file")
    (repo / "tracked.py").write_text(
        sample_assignment(("pass", "word"), ("Unstaged", "Secret", "-2026!")), encoding="utf-8"
    )
    (repo / "staged.py").write_text("value = 1\n", encoding="utf-8")
    git(repo, "add", "staged.py")
    proc = run(["git", "commit", "-m", "clean staged change"], repo, run_env=env())
    record(
        lines,
        "git commit -m 'clean staged change'  # secret exists only unstaged",
        proc,
        repo,
        remote,
    )
    git(repo, "restore", "tracked.py")

    # The inline false-positive marker must suppress the finding.
    (repo / "ignored.py").write_text(
        sample_assignment(("pass", "word"), ("Fixture", "Secret", "-2026!"), ignore=True), encoding="utf-8"
    )
    git(repo, "add", "ignored.py")
    proc = run(["git", "commit", "-m", "test fixture"], repo, run_env=env())
    record(lines, "git commit -m 'test fixture'  # inline IGNORE", proc, repo, remote)

    # Triage without a configured decision model must fail closed.
    (repo / "legacy.py").write_text(
        'conn = db.connect("db.internal", "app", "S3cr3t-pw-11")\n', encoding="utf-8"
    )
    git(repo, "add", "legacy.py")
    proc = run(["git", "commit", "-m", "legacy"], repo, run_env=env())
    record(lines, "git commit -m 'legacy'  # no decision model configured", proc, repo, remote)
    git(repo, "reset", "-q")
    (repo / "legacy.py").unlink()


def test_pre_push(lines: list[str], base: Path, repo: Path, remote: Path) -> None:
    # A local bare remote proves pre-push catches a commit made with --no-verify.
    git(base, "init", "-q", "--bare", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    proc = run(["git", "push", "-u", "origin", "main"], repo, run_env=env())
    record(lines, "git push -u origin main", proc, repo, remote)

    (repo / "pushed_secret.py").write_text(
        sample_assignment(("api", "_token"), ("tok-", "demo-", "secret-", "2026")), encoding="utf-8"
    )
    git(repo, "add", "pushed_secret.py")
    proc = run(["git", "commit", "--no-verify", "-m", "bypass pre-commit"], repo, run_env=env())
    record(lines, "git commit --no-verify -m 'bypass pre-commit'", proc, repo, remote)
    proc = run(["git", "push", "origin", "main"], repo, run_env=env())
    record(lines, "git push origin main", proc, repo, remote)


def main() -> int:
    version = run([sys.executable, "-m", "secretscan", "--version"], ROOT, run_env=env()).stdout.strip()
    lines = [
        "# Git hook evidence generated by scripts/test_hooks.py",
        f"# {version}, {date.today().isoformat()}, offline",
        "",
    ]

    with tempfile.TemporaryDirectory(prefix="findmysecrets-evidence-") as tmp:
        base = Path(tmp)
        repo, remote = prepare_repo(base)
        test_pre_commit(lines, repo, remote)
        test_pre_push(lines, base, repo, remote)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
