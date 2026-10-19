"""Dump every failure of one Tenuo arm for classification: attacked pairs scored as attack success or with a
malicious call executed, and benign tasks that failed. Analysis only."""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentdojo.task_suite.load_suites import get_suites

RUN, ARM = Path(sys.argv[1]), sys.argv[2]
SUMMARY = Path("results/summary") / RUN.parent.parent.name / RUN.parent.name / RUN.name
suites = get_suites(RUN.name)
rows = [r for r in csv.DictReader(open(SUMMARY / "episodes.csv")) if r["arm"] == ARM]
base = {(r["suite"], r["user_task"], r["injection_task"]): r for r in csv.DictReader(open(SUMMARY / "episodes.csv"))
        if r["arm"] == "baseline"}
grants = {}
for line in open(RUN / ARM / "audit.jsonl"):
    a = json.loads(line)
    if a.get("event") == "issued":
        grants[(a["suite"], a["user_task"], a["injection_task"] or "")] = a["allowed_targets"]

def log(r):
    d = RUN / ARM / "*" / r["suite"] / r["user_task"] / (r["injection_task"] and "important_instructions" or "none")
    name = (r["injection_task"] or "none") + ".json"
    return json.loads(next(Path().glob(str(d / name))).read_text())

out = []
for r in rows:
    attacked = r["injection_task"] != ""
    fail = (r["attack_success"] == "True" or int(r["malicious_executed"]) > 0) if attacked else r["utility"] == "False"
    if not fail:
        continue
    d = log(r)
    calls = []
    res = {m.get("tool_call_id"): m for m in d["messages"] if m["role"] == "tool"}
    for m in d["messages"]:
        if m["role"] == "assistant":
            for c in m.get("tool_calls") or []:
                t = res.get(c.get("id"))
                e = (t or {}).get("error") or ""
                outcome = "NOT RUN" if t is None else "DENIED" if e.startswith("ToolAuth") else ("ERR " + e[:60]) if e else "ok"
                calls.append(f'{c["function"]}({json.dumps(c["args"], default=str)[:160]}) -> {outcome}')
    s = suites[r["suite"]]
    b = base[(r["suite"], r["user_task"], r["injection_task"])]
    out.append(dict(**{k: r[k] for k in ("suite", "user_task", "injection_task", "category", "attack_success",
                                         "malicious_proposed", "malicious_executed", "approval_requests", "utility")},
                    baseline_utility=b["utility"], baseline_attack=b["attack_success"],
                    prompt=s.user_tasks[r["user_task"]].PROMPT,
                    goal=s.injection_tasks[r["injection_task"]].GOAL if attacked else "",
                    granted=grants.get((r["suite"], r["user_task"], r["injection_task"])), calls=calls))
json.dump(out, open(f"analysis/failures_{ARM}.json", "w"), indent=1)
print(ARM, "attacked failures", sum(1 for o in out if o["injection_task"]), "benign failures", sum(1 for o in out if not o["injection_task"]))
