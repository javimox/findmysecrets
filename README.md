# FindMySecrets

FindMySecrets detects hardcoded secrets in source code and Git workflows.
It combines deterministic rules, Python data-flow analysis, and optional AI review for ambiguous cases. Secret values are redacted in the output.

Python 3.11+. Runtime uses only the standard library.

## Install

Using `uv`:

```sh
uv venv
source .venv/bin/activate
uv pip install -e '.[dev]'
```

For runtime only:

```sh
uv pip install -e .
```

## Quick start

```sh
findmysecrets scan .
findmysecrets scan --staged
findmysecrets install-hook
```

Hidden files such as `.env` are scanned. `.docx` and `.ipynb` are converted to text automatically.

## Commands

| Command | Purpose |
|---|---|
| `findmysecrets scan [PATHS...]` | Scan files and directories; default path is `.` |
| `findmysecrets install-hook` | Install pre-commit and pre-push hooks |
| `findmysecrets allow ID [REASON]` | Mark one reported finding as a false positive |
| `findmysecrets --version` | Show the installed version |

### Scan options

| Option | Purpose |
|---|---|
| `--staged` | Scan the Git index: what the next commit contains |
| `--history` | Scan lines introduced by past commits; rules only |
| `--pushed REMOTE` | Scan commits being pushed; pre-push hook mode, rules only |
| `--range REVS` | Revision selection for `--history`, e.g. `origin/main..HEAD` |
| `--format text|json` | Output format; default `text` |
| `--exclude GLOB` | Exclude repository-relative paths; repeatable |
| `--min-confidence low|medium|high` | Minimum reported confidence; default `low` |
| `--show-suppressed` | Also show findings suppressed by `IGNORE` or `.secretscan-allow` |
| `--ai off|triage|full` | Select deterministic, triage, or full AI review; default `off` |
| `--decision-model MODEL` | Decision model used by `triage` |
| `--decision-url URL` | Decision API base; default `http://localhost:11434/v1` |
| `--chat-model MODEL` | Chat model used by `full` or escalated triage |
| `--chat-url URL` | OpenAI-compatible API base; default `http://localhost:11434/v1` |
| `--chat-api-key KEY` | Chat API key; prefer `SECRETSCAN_CHAT_API_KEY` |
| `--threshold P` | Decision probability threshold; default `0.5` |
| `--timeout SECONDS` | Timeout per model request; default `60` |
| `--max-ai-calls N` | Maximum model calls per scan; default `200` |

`--range` only applies to `--history`; `--pushed` is normally invoked by the installed hook. Run `findmysecrets scan --help` for the authoritative CLI help.

## Data flow and content slices

Rules catch obvious literals, while Python analysis also follows values from their definitions to credential-sensitive uses such as password arguments. For staged changes, Python flow is checked locally against the relevant source, while AI receives a content slice: changed lines plus the definitions and uses needed to understand them, with original line numbers. Other languages use a bounded lexical slice based on shared identifiers instead of Python AST data flow.

## AI modes

| Mode | Behaviour |
|---|---|
| `--ai off` | Rules and Python data flow only |
| `--ai triage` | Decision model first; chat model only when needed |
| `--ai full` | Chat model reviews every evidence pack; decision model is unused |

`triage` requires an explicitly configured decision model when a pack needs model review. `full` requires a chat model; the pre-commit hook uses `triage` unless `SECRETSCAN_AI` overrides it.

Example with local models:

```sh
export SECRETSCAN_DECISION_URL=http://localhost:11434/v1
export SECRETSCAN_DECISION_MODEL=clef-flash:latest
export SECRETSCAN_CHAT_URL=http://localhost:11434/v1
export SECRETSCAN_CHAT_MODEL=qwen3.5:9b

findmysecrets scan . --ai triage
```

AI mode, model names, URLs, and the chat API key can also be set with the corresponding `SECRETSCAN_*` environment variables. Values already confirmed locally are masked with asterisks before a model receives the evidence pack. Unresolved candidate literals remain visible so the models can classify them, so configure endpoints you trust.

HTTP redirects are never followed.

## Git hooks

```sh
findmysecrets install-hook
```

- **pre-commit** scans the Git index with rules, Python data flow, and AI triage.
- **pre-push** scans commits about to be uploaded using deterministic rules.

Run a deterministic-only commit with:

```sh
SECRETSCAN_AI=off git commit
```

Repository-specific exclusions can be configured with:

```sh
git config --add findmysecrets.exclude 'samples/*'
```

### Hook tests

Use a temporary repository so the checks do not modify your project:

```sh
TESTDIR=$(mktemp -d)
REMOTE=$(mktemp -d)/remote.git
cd "$TESTDIR"

git init -b main
git config user.name "FindMySecrets Test"
git config user.email "test@example.invalid"
printf 'print("clean")\n' > app.py
git add app.py
git commit -m "Initial clean commit"

git init --bare "$REMOTE"
git remote add origin "$REMOTE"
git push -u origin main
findmysecrets install-hook
```

**1. Pre-commit blocks a secret.** The commit should fail with exit code `1`.

```sh
cat > secret.py <<'EOT'
password = "SuperSecret-2026!"
EOT
git add secret.py
SECRETSCAN_AI=off git commit -m "Add secret"
echo "exit=$?"

git reset -- secret.py
rm secret.py
```

**2. `# IGNORE` suppresses a false positive.** The commit should succeed with exit code `0`.

```sh
cat > ignored.py <<'EOT'
TEST_PASSWORD = "fake-integration-password"  # IGNORE
EOT
git add ignored.py
SECRETSCAN_AI=off git commit -m "Add ignored test credential"
echo "exit=$?"
git push origin main
```

**3. Pre-push catches a secret committed with `--no-verify`.** The commit should succeed, but the push should fail with exit code `1`.

```sh
cat > leaked.py <<'EOT'
password = "BypassedSecret-2026!"
EOT
git add leaked.py
git commit --no-verify -m "Bypass pre-commit"
git push origin main
echo "exit=$?"
```

## False positives

In source files, add `IGNORE` to the finding's line:

```python
TEST_PASSWORD = "fake-test-password"  # IGNORE
```

For formats where comments are unsuitable:

```sh
findmysecrets allow FINDING_ID "test credential"
```

Each finding has a stable ID derived from its file, detection rule, and secret value. The ID lets you suppress a reviewed false positive with `findmysecrets allow <ID> "reason"`. Approved IDs are stored in the versioned `.secretscan-allow` file, so the exception remains auditable and stops applying if the secret value changes.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Complete scan, no findings |
| `1` | Findings detected |
| `2` | Usage or Git error |
| `3` | Analysis incomplete |

If AI fails, deterministic findings are still reported and the scan is marked incomplete.

## Limits

- Deep data-flow analysis is Python-specific.
- Pre-push and history scans use deterministic rules only.
- Files over 10 MB are not analysed and make the scan incomplete.
- AI latency and accuracy depend on the configured models.
- No scanner can guarantee detection of every secret.

## Background

FindMySecrets was originally developed as part of a Master's program in Artificial Intelligence Applied to Cybersecurity.
