# Live-model validation

The test suite uses fake model responses. These checks exercise real decision and chat endpoints; keep the outputs you want to retain under `docs/evidence/`.

## Setup

Configure both models explicitly. The decision endpoint must support Ollama's `/v1/systemone`; the chat endpoint must be OpenAI-compatible.

```sh
export SECRETSCAN_DECISION_MODEL="<decision-model>"
export SECRETSCAN_DECISION_URL="http://localhost:11434/v1"
export SECRETSCAN_CHAT_MODEL="<chat-model>"
export SECRETSCAN_CHAT_URL="http://localhost:11434/v1"
# export SECRETSCAN_CHAT_API_KEY="..."   # only when the chat endpoint needs one
```

FindMySecrets reads these environment variables:

| Variable | Purpose |
|---|---|
| `SECRETSCAN_AI` | Default AI mode for `scan`; the pre-commit hook uses `triage` when unset |
| `SECRETSCAN_DECISION_MODEL` | Decision model used by `triage` |
| `SECRETSCAN_DECISION_URL` | Decision API base; default `http://localhost:11434/v1` |
| `SECRETSCAN_CHAT_MODEL` | Chat model used by `full` or escalated triage |
| `SECRETSCAN_CHAT_URL` | Chat API base; default `http://localhost:11434/v1` |
| `SECRETSCAN_CHAT_API_KEY` | Optional bearer token for the chat endpoint |

`--threshold`, `--timeout`, and `--max-ai-calls` are CLI-only settings. If one Ollama instance serves both models, `OLLAMA_MAX_LOADED_MODELS=2` and `OLLAMA_KEEP_ALIVE=30m` can keep them resident; `OLLAMA_HOST` is only needed when configuring the Ollama server itself.

Before validating, make one decision request and one chat request and verify that the intended models are loaded. Use only synthetic secrets.

## Checks

1. **Decision model contract.** Run `findmysecrets scan samples/flow_cases.py --ai triage --format json > docs/evidence/flow_triage.json`. Expect no `incomplete` entry; weak flow candidates should receive `decision model p=` when classified above the threshold, and the chat model is called only when the decision model also flags remaining uncategorized literals through `other`.
2. **Reference files with AI.** Run `findmysecrets scan samples/app.py samples/FicheroT2.docx --ai triage`. The strong `valid_password` finding should match `--ai off` and be masked before model review; a chat call should happen only if remaining literals are considered suspicious.
3. **Negative cases.** Run `findmysecrets scan samples/negative_cases.py --ai triage`. It should report no findings and no incomplete analysis.
4. **Chat citations.** Run `findmysecrets scan samples --ai full --format json > docs/evidence/samples_full.json`. Any `ai-*` finding must cite a real literal; an answer containing only invalid literal ids is retried once, then leaves the file incomplete if still unusable.
5. **Git hook.** In a throwaway repository, install the hooks and verify that a staged secret is blocked, an unstaged secret is ignored, `# IGNORE` passes, and an unavailable configured model makes the pre-commit analysis incomplete. Keep offline hook evidence separately in `docs/evidence/hook_offline.txt`.
6. **Cost.** Compare the time and model-call counts printed by `--ai triage` and `--ai full` on `samples/`. If a chat request needs more than the default 60 seconds during benchmarking, repeat that run with `--timeout 120` rather than changing the hook default without repeated measurements.
