"""Replay logged episodes against a fresh environment and re-score them. No model calls.

Each episode's environment is rebuilt from the suite, the logged injections and the user task's init. Every call
whose logged tool result has no error is executed again, in order; a denied or failed call is not. Then
AgentDojo's own utility and security checks run on the replayed state and are compared with the logged scores.
This tests the assumption analyze.py makes (a result without an error means the call ran, an error means it did
not) and shows what each executed call changed.

Expected differences: wall-clock timestamps on new emails and files (normalised away); arms whose pipeline rewrites
tool output (contract_gate); and episodes AgentDojo retried after the model ended without a final message, where
earlier attempts changed the environment but only the last attempt is logged (see analyze.audit_by_episode).

Usage:
  replay_episode.py RUN_ROOT ARM SUITE USER_TASK [INJECTION_TASK]   one episode, every call and its state change
  replay_episode.py RUN_ROOT --all                                  every episode; prints score mismatches
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

_TS = re.compile(r"(timestamp|last_modified): '?\d{4}-\d{2}-\d{2}[ T][\d:.]+'?")


def norm_ts(text: str) -> str:
    return _TS.sub(r"\1: <now>", text)


def flat(o, pre: str = "") -> dict:
    if hasattr(o, "model_dump"):
        o = o.model_dump()
    if isinstance(o, dict):
        return {k: v for key, val in o.items() for k, v in flat(val, f"{pre}.{key}" if pre else str(key)).items()}
    if isinstance(o, list):
        return {k: v for i, val in enumerate(o) for k, v in flat(val, f"{pre}[{i}]").items()}
    return {pre: o}


def changed(before, after) -> list[str]:
    fa, fb = flat(before), flat(after)
    return sorted({re.sub(r"\[\d+\]", "", k).rsplit(".", 1)[0] for k in set(fa) | set(fb) if fa.get(k) != fb.get(k)})


def replay(suites, log: Path) -> dict:
    d = json.loads(log.read_text())
    suite = suites[d["suite_name"]]
    user_task = suite.user_tasks[d["user_task_id"]]
    iid = d.get("injection_task_id")
    env = user_task.init_environment(suite.load_and_inject_default_environment(d["injections"] or {}))
    pre = env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    msgs = d["messages"] or []
    results = {m.get("tool_call_id"): m for m in msgs if m["role"] == "tool"}
    steps, trace = [], []
    for m in msgs:
        for c in (m.get("tool_calls") or []) if m["role"] == "assistant" else []:
            trace.append(FunctionCall(function=c["function"], args=c["args"], id=c.get("id")))
            res = results.get(c.get("id"))
            step = {"function": c["function"], "args": c["args"]}
            if res is None or res.get("error"):
                steps.append({**step, "executed": False, "logged_error": (res or {}).get("error", "no tool result")})
                continue
            before = env.model_copy(deep=True)
            out, err = runtime.run_function(env, c["function"], c["args"])
            logged = "".join(b.get("content") or "" for b in res["content"]) if isinstance(res["content"], list) \
                else str(res["content"])
            steps.append({**step, "executed": err is None, "replay_error": err,
                          "output_matches_log": err is None and norm_ts(tool_result_to_str(out)) == norm_ts(logged),
                          "changed": changed(before, env)})
    output = (msgs[-1].get("content") if msgs and msgs[-1]["role"] == "assistant" else None) or []
    return {
        "suite": d["suite_name"], "user_task": d["user_task_id"], "injection_task": iid,
        "logged": {"utility": d["utility"], "security": d["security"]},
        "replayed": {"utility": suite._check_task_result(user_task, output, pre, env, trace),
                     "security": suite._check_task_result(suite.injection_tasks[iid], output, pre, env, trace)
                     if iid else None},
        "steps": steps,
    }


def episode_logs(root: Path, arm: str):
    for log in sorted((root / arm).rglob("*.json")):
        if log.name.startswith(("results_", "._")) or log.parent.name not in ("none", "important_instructions"):
            continue
        if not log.parts[-3].startswith("injection_task"):
            yield log


def main() -> None:
    root = Path(sys.argv[1])
    suites = get_suites(root.name)
    if sys.argv[2] != "--all":
        arm, suite, user_task = sys.argv[2:5]
        iid = sys.argv[5] if len(sys.argv) > 5 else None
        base = root / arm / f"{root.parent.name}-{arm}" / suite / user_task
        log = base / "important_instructions" / f"{iid}.json" if iid else base / "none" / "none.json"
        print(json.dumps(replay(suites, log), indent=1, default=str))
        return
    for arm in sorted(p.name for p in root.iterdir() if p.is_dir()):
        counts = collections.Counter()
        for log in episode_logs(root, arm):
            if "utility" not in json.loads(log.read_text()):
                continue
            r = replay(suites, log)
            counts["episodes"] += 1
            counts["episodes with a tool output that differs from the log"] += any(
                s["executed"] and not s["output_matches_log"] for s in r["steps"])
            for metric in ("utility", "security"):
                if r["logged"][metric] != r["replayed"][metric] and (metric == "utility" or r["injection_task"]):
                    counts[f"{metric} differs"] += 1
                    print(f"  {arm} {r['suite']} {r['user_task']} {r['injection_task']}: {metric} logged "
                          f"{r['logged'][metric]}, replayed {r['replayed'][metric]}")
        print(arm, dict(counts))


if __name__ == "__main__":
    main()
