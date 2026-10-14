from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from secretscan.scanner import Options, Report, Snapshot, Source, analyze_source

ROOT = Path(__file__).resolve().parents[1]


def kv(key: str, value: str, sep: str = " = ", quote: str = '"') -> str:
    """Build `key = "value"` at runtime, so that test files hold no literal secrets
    and the repository passes its own scanner (see test_repo_is_clean.py)."""
    return f"{key}{sep}{quote}{value}{quote}"


def scan_snippet(text: str, path: str = "app.py", opts: Options = Options()) -> Report:
    """Run rules and data flow on an in-memory file (no AI, no disk)."""
    report = Report("files")
    analyze_source(Source(path, text, None), Snapshot(lambda _: None), opts, None, report)
    return report


@pytest.fixture
def isolated_git(monkeypatch):
    """Git without the user's global configuration (gpgsign, hooksPath, noprefix...)."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for who in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{who}_NAME", "Test")
        monkeypatch.setenv(f"GIT_{who}_EMAIL", "test@example.invalid")


class Repo:
    """Throwaway Git repository for staged and history modes."""

    def __init__(self, path: Path):
        self.path = path
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.path, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, name: str, *lines: str) -> None:
        file = self.path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path, isolated_git) -> Repo:
    return Repo(tmp_path)


def run_cli(args: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    """`python -m secretscan` exactly as a reviewer would run it."""
    full_env = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run([sys.executable, "-m", "secretscan", *args], cwd=cwd, env=full_env,
                          capture_output=True, text=True, encoding="utf-8", check=False)


class FakeOllama:
    """Local stand-in for Ollama: /v1/systemone (decision model) and /v1/chat/completions (chat model)."""

    def __init__(self, decide=None, chat=None):
        self.decide = decide or (lambda body: {q: 0.0 for q in body["questions"]})
        self.chat = chat or (lambda body: {"findings": []})
        self.requests: list[tuple[str, dict]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append((self.path, body))
                if self.path == "/v1/systemone":
                    data = {"answers": {q: {"type": "noul", "noul": p} for q, p in fake.decide(body).items()}}
                else:
                    content = fake.chat(body)
                    data = {"choices": [{"message": {"content": content if isinstance(content, str)
                                                     else json.dumps(content)}}]}
                raw = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ollama():
    servers: list[FakeOllama] = []

    def start(decide=None, chat=None) -> FakeOllama:
        servers.append(FakeOllama(decide, chat))
        return servers[-1]

    yield start
    for s in servers:
        s.close()
