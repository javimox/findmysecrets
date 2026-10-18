"""Command line.

    findmysecrets scan [PATHS...]               files and directories (default: .)
    findmysecrets scan --staged                 the Git index (what the next commit contains)
    findmysecrets scan --history [--range R]    lines added by past commits (rules only)
    findmysecrets scan --pushed REMOTE          the commits a push uploads (run by the pre-push hook)
    findmysecrets install-hook                  pre-commit and pre-push hooks for the current repository
    findmysecrets allow ID [REASON]             mark a reported finding as a false positive

Exit codes: 0 clean, 1 findings, 2 usage or Git error, 3 incomplete analysis.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .ai import AIConfig, clean
from .scanner import ALLOW_FILE, Options, Report, ScanError, pushed_revs, redact, repo_root, scan, scan_history

EXIT_ERROR = 2
HOOKS = {
    "pre-commit": "# Deterministic-only run: SECRETSCAN_AI=off git commit ...\n"
                  'exec {python} -m secretscan scan --staged --ai "${{SECRETSCAN_AI:-triage}}" --format text\n',
    "pre-push": "# Git passes the remote name, and the refs being pushed on standard input.\n"
                'exec {python} -m secretscan scan --pushed "$1" --ai off --format text\n',
}
BLOCKED = {     # (mode, findings?) -> what the hook tells the user
    ("staged", True): "Commit blocked: remove the secret (rotate it if it was ever pushed), or mark a false "
                      "positive with '# IGNORE' on its line or 'findmysecrets allow <id>'.",
    ("staged", False): "Commit blocked: the analysis is incomplete. Fix the model setup, or commit with "
                       "SECRETSCAN_AI=off for a deterministic-only check.",
    ("push", True): "Push blocked: remove the secret from the commits listed (git commit --amend, git rebase -i), "
                    "or mark a false positive with 'findmysecrets allow <id>'.",
    ("push", False): "Push blocked: the analysis is incomplete.",
}


def build_parser() -> argparse.ArgumentParser:
    env = os.environ.get
    parser = argparse.ArgumentParser(
        prog="findmysecrets",
        description="Find hardcoded secrets in files and Git changes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install-hook", help="install the pre-commit and pre-push hooks in the current repository")
    allow = sub.add_parser("allow", help=f"mark a finding as a false positive (listed in {ALLOW_FILE})")
    allow.add_argument("id", help="finding id, as printed by 'findmysecrets scan'")
    allow.add_argument("reason", nargs="?", default="", help="why it is not a secret (kept as a comment)")

    p = sub.add_parser("scan", help="scan files, the Git index or the Git history")
    p.add_argument("paths", nargs="*", help="files or directories (default: .)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan the Git index (what the next commit contains)")
    mode.add_argument("--history", action="store_true", help="scan lines added by past commits (rules only)")
    mode.add_argument("--pushed", metavar="REMOTE",
                      help="the commits 'git push' uploads, as the pre-push hook lists them on stdin (rules only)")
    p.add_argument("--range", dest="rev_range", metavar="REVS", help="commits for --history, e.g. 'origin/main..HEAD'")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="repository-relative paths to leave out (repeatable)")
    p.add_argument("--min-confidence", choices=("low", "medium", "high"), default="low")
    p.add_argument("--show-suppressed", action="store_true",
                   help=f"audit: also report findings marked IGNORE or listed in {ALLOW_FILE}")

    ai = p.add_argument_group("AI (endpoints default to local Ollama)")
    ai.add_argument("--ai", choices=("off", "triage", "full"), default=env("SECRETSCAN_AI", "off"),
                    help="off: rules and data flow; triage: the decision model decides, the chat model "
                         "locates; full: chat model on every pack")
    ai.add_argument("--chat-model", default=env("SECRETSCAN_CHAT_MODEL", ""),
                    help="chat model for --ai full or escalated triage")
    ai.add_argument("--chat-url", default=env("SECRETSCAN_CHAT_URL", AIConfig.chat_url),
                    help="OpenAI-compatible API base, ending in /v1")
    ai.add_argument("--chat-api-key", default=env("SECRETSCAN_CHAT_API_KEY", ""),
                    help="prefer SECRETSCAN_CHAT_API_KEY (command lines are visible to other users)")
    ai.add_argument("--decision-model", default=env("SECRETSCAN_DECISION_MODEL", ""),
                    help="decision model for --ai triage")
    ai.add_argument("--decision-url", default=env("SECRETSCAN_DECISION_URL", AIConfig.decision_url),
                    help="Ollama decision API base, ending in /v1")
    ai.add_argument("--threshold", type=float, default=AIConfig.threshold,
                    help="decision-model probability that counts as yes")
    ai.add_argument("--timeout", type=float, default=AIConfig.timeout, help="seconds per model request")
    ai.add_argument("--max-ai-calls", type=int, default=AIConfig.max_calls)
    return parser


def _ai_config(args: argparse.Namespace, parser: argparse.ArgumentParser) -> AIConfig:
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")
    if args.timeout <= 0 or args.max_ai_calls <= 0:
        parser.error("--timeout and --max-ai-calls must be positive")
    for url in (args.chat_url, args.decision_url):
        if urlsplit(url).scheme not in ("http", "https"):
            parser.error(f"model URLs must use http or https: {url}")
    return AIConfig(
        mode=args.ai,
        decision_url=args.decision_url,
        decision_model=args.decision_model,
        chat_url=args.chat_url,
        chat_model=args.chat_model,
        chat_api_key=args.chat_api_key,
        threshold=args.threshold,
        timeout=args.timeout,
        max_calls=args.max_ai_calls,
    )


def to_json(report: Report) -> str:
    return json.dumps({"tool": "findmysecrets", "version": __version__, "mode": report.mode, "ai": report.ai,
                       "findings": [f.to_dict() for f in report.findings], "summary": report.summary(),
                       "incomplete": report.incomplete}, indent=2, ensure_ascii=False)


def _printable(text: str) -> str:
    """File names and code reach the terminal: control characters could rewrite the report."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _style(text: str, code: str, color: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if color else text


def _count(n: int, noun: str) -> str:
    return f"{n} {noun if n == 1 else noun + 's'}"


def to_text(report: Report, *, color: bool = False) -> str:
    """Human-readable report. ANSI color is opt-in so pipes, files and tests stay plain."""
    out: list[str] = []
    confidence_style = {"high": "1;31", "medium": "1;33", "low": "1;34"}

    for i, f in enumerate(report.findings):
        if i:
            out.append("")
        r = redact(f.secret)
        where = _printable(f"{f.file}:{f.line}:{f.column}") + (f" (commit {f.commit[:10]})" if f.commit else "")
        key = f"{_printable(f.key)} = " if f.key else ""
        value = f"{key}{r['prefix']}...{r['suffix']}"
        severity = _style(f"{f.confidence.upper():<7}", confidence_style.get(f.confidence, "1"), color)
        rule = _style(f"{_printable(f.rule):<22}", "1", color)

        out.append(_style(where, "1;36", color))
        out.append(f"  {severity} {rule} {value}")
        out.append(f"  {_style('why   ', '1;36', color)} {_printable('; '.join(f.why))}")
        out.append(f"  {_style('via   ', '1;35', color)} {' → '.join(f.found_by)}")
        out.append(f"  {_style('id    ', '2', color)} {f.id}")

    if report.findings:
        out.append("")
    s = report.summary()
    summary = f"{_count(s['findings'], 'finding')} in {_count(s['files_scanned'], 'file')}"
    if "commits_scanned" in s:
        summary += f" across {_count(s['commits_scanned'], 'commit')}"
    details = []
    for key, label in (("suppressed", "suppressed"), ("files_skipped", "skipped"), ("excluded", "excluded")):
        if s[key]:
            details.append(f"{s[key]} {label}")
    if details:
        summary += " | " + " | ".join(details)
    summary_code = "1;31" if s["findings"] else "1;32"
    out.append(_style(summary, summary_code, color))

    if report.ai == "off":
        scope = "rules only" if "commits_scanned" in s else "rules + data flow"
        out.append(f"AI mode: off ({scope})")
    else:
        decision_calls = s["ai_calls"] - s["chat_calls"]
        out.append(f"AI mode: {report.ai}")
        out.append(f"Decision model calls: {decision_calls}")
        out.append(f"LLM chat calls: {s['chat_calls']}")
        out.append(f"Total AI calls: {s['ai_calls']}")
        if s["unverified"]:
            out.append(f"Unverified citations: {s['unverified']}")

    out += [_style(f"INCOMPLETE: {_printable(msg)}", "1;33", color) for msg in report.incomplete]
    if report.exit_code and (blocked := BLOCKED.get((report.mode, bool(report.findings)))):
        out.append(_style(blocked, "1;31", color))
    return "\n".join(out)


def install_hooks(cwd: Path) -> list[Path]:
    """Write the pre-commit and pre-push hooks (in .git/hooks or core.hooksPath); never overwrite
    a foreign hook, and write none if one is in the way."""
    root = repo_root(cwd)
    git_paths = subprocess.run(["git", "rev-parse", *(a for h in HOOKS for a in ("--git-path", f"hooks/{h}"))],
                               cwd=root, capture_output=True, text=True, check=False)
    if git_paths.returncode:
        raise ScanError("install-hook must run inside a Git repository")
    hooks = [(root / p).resolve() for p in git_paths.stdout.splitlines()]
    for hook in hooks:
        if hook.exists() and "# Installed by FindMySecrets." not in hook.read_text(errors="replace"):
            raise ScanError(f"an existing hook would be overwritten: {hook}")
    for hook, body in zip(hooks, HOOKS.values(), strict=True):
        try:
            hook.parent.mkdir(parents=True, exist_ok=True)
            hook.write_text(
                "#!/bin/sh\n# Installed by FindMySecrets.\n"
                + body.format(python=shlex.quote(sys.executable))
            )
            hook.chmod(0o755)
        except OSError as exc:              # e.g. core.hooksPath=/dev/null disables hooks
            raise ScanError(f"cannot write {hook}: {exc.strerror}") from exc
    return hooks


def allow(cwd: Path, finding_id: str, reason: str) -> Path:
    """Add a finding id to the allow file at the repository root (once)."""
    if not re.fullmatch(r"[0-9a-f]{12}", finding_id):
        raise ScanError("expected a 12-character finding id, as printed by 'findmysecrets scan'")
    path = repo_root(cwd) / ALLOW_FILE
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if not re.search(rf"^\s*{finding_id}\b", current, re.MULTILINE):
        entry = f"{finding_id}  # {clean(reason)}" if reason.strip() else finding_id
        path.write_text(current + ("\n" if current and not current.endswith("\n") else "") + entry + "\n",
                        encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "install-hook":
            for hook in install_hooks(Path.cwd()):
                print(f"{hook.name} hook installed: {hook}")
            return 0
        if args.command == "allow":
            path = allow(Path.cwd(), args.id, args.reason)
            print(f"{args.id} listed in {path}; commit that file so that the hook and every clone apply it")
            return 0
        if args.rev_range and not args.history:
            parser.error("--range requires --history")
        commits = args.history or args.pushed is not None
        if args.paths and (args.staged or commits):
            parser.error("paths cannot be combined with --staged, --history or --pushed")
        if commits and args.ai != "off":
            parser.error("--history and --pushed run rules only; use --ai off")
        opts = Options(tuple(args.exclude), not args.show_suppressed, args.min_confidence)
        if args.pushed is not None:
            report = scan_history(Path.cwd(), pushed_revs(sys.stdin.read(), args.pushed), opts, "push")
        elif args.history:
            report = scan_history(Path.cwd(), shlex.split(args.rev_range or "--all"), opts)
        else:
            report = scan(args.paths, Path.cwd(), "staged" if args.staged else "files", opts, _ai_config(args, parser))
    except ScanError as exc:
        print(f"findmysecrets: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    color = args.format == "text" and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(to_json(report) if args.format == "json" else to_text(report, color=color))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
