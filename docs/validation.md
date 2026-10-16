# Live-model validation

The test suite replaces the models with a fake server. These checks use the real
ones; run them once and keep the outputs in `docs/evidence/`.

## Setup

```sh
ollama --version                  # >= 0.35.1 (decision models: POST /v1/systemone)
ollama pull clef-flash
ollama pull <chat model>          # prefer a model that runs on this machine
export SECRETSCAN_DECISION_MODEL=clef-flash
export SECRETSCAN_CHAT_MODEL=<chat model>    # URLs default to http://localhost:11434/v1
```

Before the checks, make one decision and one chat request, then run `ollama ps` on each
server: both models must be loaded, at `100% GPU`. If one Ollama serves both, set
`OLLAMA_MAX_LOADED_MODELS=2` and `OLLAMA_KEEP_ALIVE=30m` there (see the README, *AI modes*).

## Checks

1. **Decision model contract.** One request with several `noul` questions:
   `findmysecrets scan samples/flow_cases.py --ai triage --format json > docs/evidence/flow_triage.json`.
   Expected: no `incomplete` entry; `mailbox` (line 16) and `opts_value` (line 17) reported
   as `credential-flow` with a `decision model p=` reason if the decision model judges them secrets.
   The concatenated token on line 34 is one finding. One decision request (questions `C1`, `C2`,
   `other`); the chat model is called only if the decision model answers `other` at or above the
   threshold. Record `chat_calls`: values already reported are masked, so it measures real suspicion.
2. **Reference file with AI.** `findmysecrets scan samples/app.py samples/FicheroT2.docx --ai triage`
   gives the same finding per file as `--ai off`: one decision request per file, whose pack shows
   `valid_password` masked; a chat call means the decision model suspected one of the remaining
   literals (`admin`, prompts, SQL).
3. **Negative cases.** `findmysecrets scan samples/negative_cases.py --ai triage` reports nothing.
4. **Chat model citations.** `findmysecrets scan samples --ai full --format json` reports
   `unverified: 0` or few; any `ai-*` finding points at a real literal. A chat answer that cites
   only invalid ids is asked again once; a second one leaves that file incomplete.
5. **Hook, in a throwaway repository.** After `findmysecrets install-hook`:
   a staged secret blocks the commit, an unstaged one does not, a line marked `# IGNORE`
   passes, and stopping Ollama blocks the commit as *incomplete* (exit 3).
   Save the terminal output as `docs/evidence/hook.txt`.
6. **Cost.** Note the time and number of calls printed by `--ai triage` and `--ai full`
   on `samples/` (summary line) to compare both modes. If the chat model needs more than
   the default 60 seconds during this benchmark, repeat the `full` run with `--timeout 120`;
   keep the hook default unchanged unless repeated measurements justify raising it.

Use synthetic secrets only.
