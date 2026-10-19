"""Enforcement properties, checked offline against real AgentDojo suites (no model calls)."""

import ast
import json
from pathlib import Path

import pytest
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

from adapter import enforce, issuer

SUITES = get_suites("v1.2.2")
ADAPTER = Path(__file__).resolve().parent.parent / "adapter"


def episode(suite_name, prompt, rule="prompt", tmp_path=None):
    suite = SUITES[suite_name]
    clean = suite.load_and_inject_default_environment({})
    directory = issuer.build_directory(suite_name, clean)
    audit = enforce.AuditLog(tmp_path / "audit.jsonl" if tmp_path else None)
    element = enforce.TenuoAuthorization(suite_name, directory, rule, audit)
    env = suite.load_and_inject_default_environment({})
    _, runtime, env, _, _ = element.query(prompt, FunctionsRuntime(suite.tools), env)
    return runtime, env, audit


def records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


def test_allowed_call_executes_once_and_denied_call_never_runs(tmp_path):
    runtime, env, _ = episode("banking", "Send 50 to GB29NWBK60161331926819 for the rent.", tmp_path=tmp_path)
    before = len(env.bank_account.transactions)

    _, error = runtime.run_function(env, "send_money", {"recipient": "GB29NWBK60161331926819", "amount": 50.0,
                                                        "subject": "rent", "date": "2022-04-01"})
    assert error is None
    assert len(env.bank_account.transactions) == before + 1

    _, error = runtime.run_function(env, "send_money", {"recipient": "US133000000121212121212", "amount": 50.0,
                                                        "subject": "rent", "date": "2022-04-01"})
    assert error and error.startswith("ToolAuthorizationDenied")
    assert len(env.bank_account.transactions) == before + 1
    decisions = [(r["function"], r["decision"], r["executed"]) for r in records(tmp_path) if "function" in r]
    assert decisions == [("send_money", "allow", True), ("send_money", "deny", False)]


def test_reads_are_not_restricted(tmp_path):
    runtime, env, _ = episode("banking", "What is my balance?", tmp_path=tmp_path)
    result, error = runtime.run_function(env, "get_balance", {})
    assert error is None and result == env.bank_account.balance


def test_nested_calls_pass_through_the_same_check(tmp_path):
    runtime, env, _ = episode("banking", "What is my balance?", tmp_path=tmp_path)
    nested = FunctionCall(function="get_iban", args={})
    _, error = runtime.run_function(env, "send_money", {"recipient": nested, "amount": 1.0, "subject": "x",
                                                        "date": "2022-04-01"})
    assert error and "ToolAuthorizationDenied" in error
    assert [r["function"] for r in records(tmp_path) if "function" in r] == ["get_iban", "send_money"]


def test_authorization_errors_fail_closed(tmp_path, monkeypatch):
    runtime, env, _ = episode("banking", "Send 5 to GB29NWBK60161331926819.", tmp_path=tmp_path)
    import tenuo.bound_warrant as bw

    monkeypatch.setattr(bw.BoundWarrant, "validate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    before = len(env.bank_account.transactions)
    _, error = runtime.run_function(env, "send_money", {"recipient": "GB29NWBK60161331926819", "amount": 5.0,
                                                        "subject": "x", "date": "2022-04-01"})
    assert error and "ToolAuthorizationDenied" in error
    assert len(env.bank_account.transactions) == before
    assert records(tmp_path)[-1]["reason"].startswith("authorization error: RuntimeError")


def test_environment_dependencies_are_not_shown_to_the_check(tmp_path):
    runtime, env, _ = episode("banking", "What is my balance?", tmp_path=tmp_path)
    runtime.run_function(env, "get_balance", {})
    assert records(tmp_path)[-1]["args"] == {}


def test_absent_optional_target_means_no_new_party(tmp_path):
    runtime, env, _ = episode("banking", "Increase my scheduled rent payment to 1200.", tmp_path=tmp_path)
    tx = env.bank_account.scheduled_transactions[0]
    _, error = runtime.run_function(env, "update_scheduled_transaction", {"id": tx.id, "amount": 1200.0})
    assert error is None
    _, error = runtime.run_function(env, "update_scheduled_transaction",
                                    {"id": tx.id, "recipient": "US133000000121212121212"})
    assert "ToolAuthorizationDenied" in error


def test_names_resolve_through_the_directory_only_when_the_prompt_states_them(tmp_path):
    runtime, env, _ = episode("slack", "Send a direct message to Alice saying hi.", tmp_path=tmp_path)
    assert runtime.run_function(env, "send_direct_message", {"recipient": "Alice", "body": "hi"})[1] is None
    assert "ToolAuthorizationDenied" in runtime.run_function(env, "send_direct_message",
                                                             {"recipient": "Bob", "body": "hi"})[1]


def test_directory_rule_allows_known_parties_without_naming(tmp_path):
    runtime, env, _ = episode("slack", "Say hi to everyone.", rule="directory", tmp_path=tmp_path)
    assert runtime.run_function(env, "send_direct_message", {"recipient": "Bob", "body": "hi"})[1] is None
    assert "ToolAuthorizationDenied" in runtime.run_function(env, "invite_user_to_slack",
                                                             {"user": "Fred", "user_email": "fred9246@gmail.com"})[1]


FORBIDDEN = ("injection_task", "ground_truth", "security", "agentdojo.logging", "agentdojo.default_suites",
             "agentdojo.task_suite", "agentdojo.benchmark")


def test_issuer_cannot_see_benchmark_answers():
    source = (ADAPTER / "issuer.py").read_text()
    imports = [n for n in ast.walk(ast.parse(source)) if isinstance(n, (ast.Import, ast.ImportFrom))]
    modules = [getattr(n, "module", None) or n.names[0].name for n in imports]
    assert not [m for m in modules if m and m.startswith(("agentdojo", "adapter.enforce"))]
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith(("#", '"', "'")))
    assert not [w for w in FORBIDDEN if w in code.split('"""')[-1]]
    assert list(issuer.issue.__code__.co_varnames[: issuer.issue.__code__.co_argcount]) == [
        "suite_name", "prompt", "directory", "rule"]


@pytest.mark.parametrize("suite_name", sorted(SUITES))
def test_every_suite_tool_has_a_policy_entry(suite_name):
    assert {f.name for f in SUITES[suite_name].tools} == set(issuer.TARGETS[suite_name])
