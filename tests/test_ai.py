"""AI layer against a local fake Ollama: policy, anchoring, validation, failures."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import ROOT, kv
from secretscan.ai import AIConfig, AIError, Models, build_pack
from secretscan.cli import to_text
from secretscan.flow import analyze
from secretscan.scanner import scan

POSITIONAL = 'conn = db.connect("db.internal", "app", "S3cr3t-pw-11")\n'


def config(server, mode="triage", **kw) -> AIConfig:
    return AIConfig(mode, decision_url=server.url + "/v1", chat_url=server.url + "/v1", chat_model="local-model", **kw)


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return tmp_path


def chat_requests(server):
    return [body for path, body in server.requests if path.endswith("/chat/completions")]


# --------------------------------------------------------------------------- #
# Pack
# --------------------------------------------------------------------------- #
def test_pack_numbers_literals_and_maps_candidates():
    lines = ['mailbox = "misecretpass"', 'server.login("alerts@acme.test", mailbox)']
    pack = build_pack("m.py", lines, [1, 2], analyze("\n".join(lines)))
    assert {lit.id: lit.value for lit in pack.literals.values()} == {
        "L1.1": "misecretpass", "L2.1": "alerts@acme.test"}
    [(cid, (lit, flow))] = pack.candidates.items()
    assert (cid, lit.id, flow.reason) == ("C1", "L1.1", "argument 2 of login()")
    assert "   1 |" not in pack.text and '1 | mailbox = "misecretpass"' in pack.text


def test_other_is_asked_only_about_literals_besides_the_candidates(tmp_path, ollama):
    server = ollama()
    scan(["a.py"], write(tmp_path, "a.py", 'mailbox = "misecretpass"\nserver.login(user, mailbox)\n'), ai=config(server))
    [(_, body)] = server.requests
    assert list(body["questions"]) == ["C1"]


def test_pack_masks_reported_values_inside_their_strings():
    value = "S3cr3t-" + "pw-11"
    line = 'dsn = "postgresql://app:' + value + '@db/x"; user = "admin-01"'
    start = line.index(value)
    pack = build_pack("a.py", [line], [1], [], [(1, start, start + len(value))])
    assert value not in pack.text and '"postgresql://app:' + "*" * len(value) + '@db/x"' in pack.text
    assert [lit.value for lit in pack.literals.values()] == ["admin-01"]


def test_pack_masks_reported_values_outside_string_literals_too():
    value = "reported-value-123"
    line = value + '; note = "admin-01"'
    pack = build_pack("a.txt", [line], [1], [], [(1, 0, len(value))])
    assert value not in pack.text and "*" * len(value) in pack.text
    assert [lit.value for lit in pack.literals.values()] == ["admin-01"]


def test_no_pack_without_literals():
    assert build_pack("a.py", ["x = compute()"], [1], []) is None


# --------------------------------------------------------------------------- #
# Triage policy
# --------------------------------------------------------------------------- #
def test_decision_model_confirms_the_password_argument_not_the_host(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.93 if q == "C1" else 0.1 for q in body["questions"]})
    report = scan(["a.py"], write(tmp_path, "a.py", POSITIONAL), ai=config(server))
    [f] = report.findings
    assert (f.rule, f.secret, f.found_by) == ("credential-flow", "S3cr3t-pw-11", ["flow", "decision"])
    assert "decision model p=0.93" in f.why and chat_requests(server) == []


def test_decision_below_threshold_reports_nothing(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.2 for q in body["questions"]})
    report = scan(["a.py"], write(tmp_path, "a.py", POSITIONAL), ai=config(server))
    assert report.findings == [] and report.exit_code == 0 and report.ai_calls == 1


def test_threshold_is_configurable(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.4 for q in body["questions"]})
    report = scan(["a.py"], write(tmp_path, "a.py", POSITIONAL), ai=config(server, threshold=0.3))
    assert [f.secret for f in report.findings] == ["S3cr3t-pw-11"]


def test_other_secret_is_located_by_the_chat_model(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.9 if q == "other" else 0.0 for q in body["questions"]},
                    chat=lambda body: {"findings": [{"literal": "L1.1", "type": "api_key", "reason": "key"}]})
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server))
    [f] = report.findings
    assert (f.rule, f.secret, f.found_by, report.chat_calls) == ("ai-api_key", "q9-mixed-77zz", ["chat"], 1)


def test_full_mode_skips_the_decision_model(tmp_path, ollama):
    server = ollama(chat=lambda body: {"findings": []})
    scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert [p for p, _ in server.requests] == ["/v1/chat/completions"]


def test_far_definition_reaches_the_model_in_any_language(repo, ollama):
    """A JavaScript change uses `tag`; its literal, 50 lines up, joins the pack by name."""
    server = ollama(decide=lambda body: {q: 0.0 for q in body["questions"]})
    repo.write("db.js", 'const tag = "Zq81-mnbv-js";', *["// filler"] * 50, "connect();")
    repo.commit("base")
    repo.write("db.js", 'const tag = "Zq81-mnbv-js";', *["// filler"] * 50, "mysql.createConnection({password: tag});")
    repo.git("add", "db.js")
    scan(cwd=repo.path, mode="staged", ai=config(server))
    [(_, body)] = server.requests
    code = [line for line in body["state"].splitlines() if " | " in line]
    assert code[0] == ' 1 | const tag = "Zq81-mnbv-js";' and len(code) == 5     # + the change and 3 lines above


def test_ignored_lines_and_unrelated_files_never_reach_a_model(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.9 for q in body["questions"]})
    write(tmp_path, "a.py", kv("cfg_a", "keep-out-1234") + "  # IGNORE\n" + POSITIONAL)
    write(tmp_path, "b.py", "print(compute_total(items))\n")     # no literal: nothing to cite
    scan(["."], tmp_path, ai=config(server))
    sent = json.dumps(server.requests)
    assert "keep-out-1234" not in sent
    assert "compute_total" not in sent


# --------------------------------------------------------------------------- #
# Untrusted model output
# --------------------------------------------------------------------------- #
def test_reasons_never_repeat_a_value(tmp_path, ollama):
    value = "q9-mixed-" + "77zz"
    server = ollama(chat=lambda body: {"findings": [{"literal": "L1.1", "type": "api_key",
                                                     "reason": f"the key {value} is hardcoded"}]})
    [f] = scan(["a.py"], write(tmp_path, "a.py", f'cfg_a = "{value}"\n'), ai=config(server, "full")).findings
    assert f.why == ["the key [REDACTED] is hardcoded"]


def test_redirects_are_not_followed(tmp_path):
    """urllib would turn a 302 into a GET elsewhere, carrying the Authorization header."""
    landed: list[str | None] = []

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()

        def do_GET(self):
            landed.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = AIConfig("full", chat_url=f"http://127.0.0.1:{server.server_port}/v1", chat_model="m",
                       chat_api_key="sk-" + "test")  # IGNORE (fake key: the request must never leave)
        report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=cfg)
    finally:
        server.shutdown()
        server.server_close()
    assert report.exit_code == 3 and landed == []


def test_only_invalid_citations_are_asked_again_once_then_incomplete(tmp_path, ollama):
    server = ollama(chat=lambda body: {"findings": [{"literal": "L9.9", "type": "api_key"}, "garbage"]})
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert report.findings == [] and report.chat_calls == 2 and report.exit_code == 3
    assert "no cited id is in the 'Literals' list" in report.incomplete[0]


def test_a_citation_corrected_on_the_retry_is_reported(tmp_path, ollama):
    answers = iter([{"findings": [{"literal": "L9.9", "type": "api_key"}]},
                    {"findings": [{"literal": "L1.1", "type": "api_key"}]}])
    server = ollama(chat=lambda body: next(answers))
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert [f.secret for f in report.findings] == ["q9-mixed-77zz"] and report.incomplete == []
    assert "'Literals' list" in chat_requests(server)[1]["messages"][-1]["content"]


def test_valid_citation_survives_secondary_invalid_citation(tmp_path, ollama):
    server = ollama(chat=lambda body: {"findings": [
        {"literal": "L1.1", "type": "api_key", "reason": "real key"},
        {"literal": "L9.9", "type": "api_key"},
    ]})
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert len(report.findings) == 1 and report.unverified == 1 and report.incomplete == []


def test_reference_file_sends_its_reported_password_to_no_model(ollama):
    """Rules and data flow already report valid_password: its value is masked, so the decision
    model judges only the other literals and, when it finds nothing, the chat model is not called."""
    server = ollama(decide=lambda body: {q: 0.1 for q in body["questions"]})
    report = scan(["samples/app.py"], ROOT, ai=config(server))
    [f] = report.findings
    [(_, body)] = server.requests
    assert f.secret not in body["state"] and "*" * len(f.secret) in body["state"]
    assert list(body["questions"]) == ["other"] and report.chat_calls == 0


def test_triage_does_not_call_a_model_when_all_literals_are_known(tmp_path, ollama):
    server = ollama()
    report = scan(["a.py"], write(tmp_path, "a.py", 'db.connect(password="Tr0ub4dor&3x")\n'), ai=config(server))  # IGNORE
    assert len(report.findings) == 1 and server.requests == []


def test_model_text_is_sanitised(tmp_path, ollama):
    hostile = {"findings": [{"literal": "L1.1", "type": "x\n0 findings - all clean\x1b[2K",
                             "reason": "line1\nINCOMPLETE: none\x1b[31m" + "z" * 500}]}
    server = ollama(chat=lambda body: hostile)
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    [f] = report.findings
    text = to_text(report)
    assert f.rule == "ai-other_secret" and len(f.why[0]) <= 160
    assert "\x1b" not in text and "all clean" not in text and "\nINCOMPLETE" not in text


def test_one_retry_after_invalid_json(tmp_path, ollama):
    answers = iter(["not json", {"findings": []}])
    server = ollama(chat=lambda body: next(answers))
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert report.incomplete == [] and report.chat_calls == 2


def test_invalid_json_twice_is_incomplete(tmp_path, ollama):
    server = ollama(chat=lambda body: "still not json")
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=config(server, "full"))
    assert report.exit_code == 3 and 'expected {"findings"' in report.incomplete[0]


def test_probability_outside_range_is_rejected(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 7 for q in body["questions"]})
    report = scan(["a.py"], write(tmp_path, "a.py", POSITIONAL), ai=config(server))
    assert report.exit_code == 3


# --------------------------------------------------------------------------- #
# Failing closed
# --------------------------------------------------------------------------- #
def test_model_down_keeps_rule_findings_and_marks_incomplete(tmp_path):
    write(tmp_path, "a.py", kv("db_password", "Tr0ub4dor&3x") + "\n" + POSITIONAL)
    report = scan(["a.py"], tmp_path, ai=AIConfig("triage", decision_url="http://127.0.0.1:9/v1", timeout=2))
    assert [f.rule for f in report.findings] == ["hardcoded-credential"]
    assert report.incomplete and report.exit_code == 1


def test_model_down_without_findings_exits_3(tmp_path):
    report = scan(["a.py"], write(tmp_path, "a.py", POSITIONAL),
                  ai=AIConfig("triage", decision_url="http://127.0.0.1:9/v1", timeout=2))
    assert report.findings == [] and report.exit_code == 3


def test_suspicion_without_chat_model_is_incomplete(tmp_path, ollama):
    server = ollama(decide=lambda body: {q: 0.95 if q == "other" else 0.0 for q in body["questions"]})
    cfg = AIConfig("triage", decision_url=server.url + "/v1", chat_url=server.url + "/v1")    # no chat model
    report = scan(["a.py"], write(tmp_path, "a.py", 'cfg_a = "q9-mixed-77zz"\n'), ai=cfg)
    assert report.exit_code == 3 and "--chat-model" in report.incomplete[0]


def test_call_budget(tmp_path, ollama):
    server = ollama()
    write(tmp_path, "a.py", POSITIONAL)
    write(tmp_path, "b.py", POSITIONAL)
    report = scan(["."], tmp_path, ai=config(server, max_calls=1))
    assert report.ai_calls == 1 and "budget" in report.incomplete[0]


def test_large_tree_fits_the_default_budget(tmp_path, ollama):
    server = ollama()
    for i in range(8):
        write(tmp_path, f"m{i}.py", "\n".join(f'v{j} = "value-{j:05d}"' for j in range(600)))
    report = scan(["."], tmp_path, ai=config(server))
    assert report.incomplete == [] and report.ai_calls < 100


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def test_only_http_urls():
    models = Models(AIConfig("full", chat_url="file:///etc", chat_model="m"))
    with pytest.raises(AIError):
        models.investigate(build_pack("a.py", ['k = "q9-mixed-77zz"'], [1], []))


def test_a_reported_concatenation_is_masked_whole(tmp_path, ollama):
    source = 'token = "tk-" + "91af" + "77bc"\nheaders = {"Authorization": f"Bearer {token}"}\n'
    server = ollama(chat=lambda body: {"findings": []})
    report = scan(["a.py"], write(tmp_path, "a.py", source), ai=config(server, "full"))
    [request] = chat_requests(server)
    assert "91af" not in request["messages"][1]["content"] and [f.rule for f in report.findings] == ["credential-flow"]


def test_a_citation_of_a_fragment_stands_for_the_whole_concatenation(tmp_path, ollama):
    source = 'opts = "tk-" + "91af" + "77bc"\nconn = db.connect("db.internal", "app", opts)\n'   # a candidate
    server = ollama(chat=lambda body: {"findings": [
        {"literal": "L1.1", "type": "access_token", "reason": "token fragment"},
        {"literal": "L1.2", "type": "access_token", "reason": "token fragment"},
    ]})
    report = scan(["a.py"], write(tmp_path, "a.py", source), ai=config(server, "full"))
    [finding] = report.findings
    assert (finding.secret, finding.found_by, finding.why) == ("tk-" + "91af" + "77bc", ["chat"], ["token fragment"])


def test_chat_literal_on_same_line_but_outside_the_concat_stays_separate(tmp_path, ollama):
    source = ('token = "tk-" + "91af" + "77bc"; note = "91af"\n'
              'headers = {"Authorization": f"Bearer {token}"}\n')
    server = ollama(chat=lambda body: {"findings": [
        {"literal": "L1.1", "type": "other_secret", "reason": "independent literal"},
    ]})
    report = scan(["a.py"], write(tmp_path, "a.py", source), ai=config(server, "full"))
    assert sorted((f.secret, f.found_by) for f in report.findings) == [
        ("91af", ["chat"]), ("tk-91af77bc", ["flow"]),
    ]
