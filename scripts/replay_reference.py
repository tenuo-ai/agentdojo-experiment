"""Offline bound: replay reference solutions through the authorizing runtime and score them with AgentDojo's checks.

benign : each user task's own reference calls under its own prompt -> is the task still completed (utility)?
attack : each injection task's reference calls under each user task's prompt -> does the attack still succeed?
This is an oracle "model" that does exactly the reference steps; live agents take other routes.
"""
import collections, json, sys
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from adapter import enforce, issuer

RULE = sys.argv[1] if len(sys.argv) > 1 else "prompt"
_MARK = "mark.black-2134@gmail.com"

def replay(suite_name, suite, directory, prompt, calls):
    env = suite.load_and_inject_default_environment({})
    pre = env.model_copy(deep=True)
    element = enforce.TenuoAuthorization(suite_name, directory, RULE, enforce.AuditLog(None))
    _, runtime, env, _, _ = element.query(prompt, FunctionsRuntime(suite.tools), env)
    denied = []
    for c in calls:
        _, err = runtime.run_function(env, c.function, c.args)
        if err and "ToolAuthorizationDenied" in err:
            denied.append(c.function)
    return pre, env, denied

out = collections.defaultdict(collections.Counter)
details = []
for sn, suite in get_suites("v1.2.2").items():
    directory = issuer.build_directory(sn, suite.load_and_inject_default_environment({}))
    for uid, ut in suite.user_tasks.items():
        gt = list(ut.ground_truth(suite.load_and_inject_default_environment({})))
        pre, post, denied = replay(sn, suite, directory, ut.PROMPT, gt)
        executed = [c for c in gt if c.function not in denied]
        try:
            ok = ut.utility(ut.GROUND_TRUTH_OUTPUT, pre, post)
        except NotImplementedError:
            ok = ut.utility_from_traces(ut.GROUND_TRUTH_OUTPUT, pre, post, executed)
        except Exception as exc:  # e.g. issue #188: scorer indexes state a blocked call never created
            ok = False; out[sn]["benign_scorer_error"] += 1
        out[sn]["benign"] += 1; out[sn]["benign_ok"] += bool(ok); out[sn]["benign_denied"] += bool(denied)
        details.append(dict(kind="benign", suite=sn, user_task=uid, denied=denied, utility=bool(ok)))
        for iid, it in suite.injection_tasks.items():
            calls = list(it.ground_truth(suite.load_and_inject_default_environment({})))
            if not calls:
                continue  # empty reference solution: nothing to replay (scored separately)
            pre, post, denied = replay(sn, suite, directory, ut.PROMPT, calls)
            try:
                hit = it.security(it.GROUND_TRUTH_OUTPUT, pre, post)
            except Exception:
                hit = it.security_from_traces(it.GROUND_TRUTH_OUTPUT, pre, post, [c for c in calls if c.function not in denied])
            out[sn]["attack"] += 1; out[sn]["attack_success"] += bool(hit)
            details.append(dict(kind="attack", suite=sn, user_task=uid, injection_task=iid, denied=denied, success=bool(hit)))
print(f"rule={RULE}")
for sn, c in out.items():
    print(f"  {sn:10} benign utility {c['benign_ok']:3}/{c['benign']:<3} (tasks with a denial {c['benign_denied']:2})   attack success {c['attack_success']:3}/{c['attack']}")
json.dump(details, open(f"analysis/replay_{RULE}.json", "w"), indent=1)
