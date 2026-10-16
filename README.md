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

Hidden files such as `.env` are scanned. Use `--exclude GLOB` to skip paths.

## Scan modes

| Command | Purpose |
|---|---|
| `findmysecrets scan PATH...` | Scan files/directories recursively |
| `findmysecrets scan --staged` | Scan what the next commit contains |
| `findmysecrets scan --history [--range REV]` | Scan secrets introduced by previous commits |

`.docx` and `.ipynb` are converted to text automatically.

## AI modes

| Mode | Behaviour |
|---|---|
| `--ai off` | Rules + Python data flow |
| `--ai triage` | **Recommended.** Decision model first; chat model only when needed |
| `--ai full` | Chat model reviews every evidence pack |

Example with local models:

```sh
export SECRETSCAN_DECISION_URL=http://localhost:11434/v1
export SECRETSCAN_DECISION_MODEL=clef-flash:latest
export SECRETSCAN_CHAT_URL=http://localhost:11434/v1
export SECRETSCAN_CHAT_MODEL=qwen3.5:9b

findmysecrets scan . --ai triage
```

Values already confirmed locally are masked before AI review. HTTP redirects are never followed.

## Git hooks

```sh
findmysecrets install-hook
```

- **pre-commit** scans the Git index with rules, Python data flow and AI triage.
- **pre-push** scans commits about to be uploaded using deterministic rules.

Repository-specific exclusions:

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
cat > secret.py <<'EOF'
password = "SuperSecret-2026!"
EOF
git add secret.py
SECRETSCAN_AI=off git commit -m "Add secret"
echo "exit=$?"

git reset -- secret.py
rm secret.py
```

**2. `# IGNORE` suppresses a false positive.** The commit should succeed with exit code `0`.

```sh
cat > ignored.py <<'EOF'
TEST_PASSWORD = "fake-integration-password"  # IGNORE
EOF
git add ignored.py
SECRETSCAN_AI=off git commit -m "Add ignored test credential"
echo "exit=$?"
git push origin main
```

**3. Pre-push catches a secret committed with `--no-verify`.** The commit should succeed, but the push should fail with exit code `1`.

```sh
cat > leaked.py <<'EOF'
password = "BypassedSecret-2026!"
EOF
git add leaked.py
git commit --no-verify -m "Bypass pre-commit"
git push origin main
echo "exit=$?"
```

## False positives

In source files:

```python
TEST_PASSWORD = "fake-test-password"  # IGNORE
```

For formats where comments are unsuitable:

```sh
findmysecrets allow FINDING_ID "test credential"
```

Each finding has a stable ID derived from its file, detection rule, and secret value.
The ID lets you suppress a reviewed false positive with `findmysecrets allow <ID> "reason"`.
Approved IDs are stored in the versioned `.secretscan-allow` file, so the exception remains auditable and stops applying if the secret value changes.

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
- Pre-push uses deterministic rules only.
- AI latency and accuracy depend on the configured models.
- No scanner can guarantee detection of every secret.

For all options:

```sh
findmysecrets --help
findmysecrets scan --help
```

## Background

FindMySecrets was originally developed as part of a Master's program in Artificial Intelligence Applied to Cybersecurity.
