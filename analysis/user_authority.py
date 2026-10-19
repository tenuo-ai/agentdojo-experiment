"""For each user task: which argument values of its state-changing reference calls are written in the prompt."""
import json, re, collections
from agentdojo.task_suite.load_suites import get_suites
from classify_pairs import WRITE, scalars, norm
out = []
for sn, suite in get_suites("v1.2.2").items():
    env = suite.load_and_inject_default_environment({})
    for uid, ut in suite.user_tasks.items():
        prompt = ut.PROMPT.lower()
        writes = [c for c in ut.ground_truth(env.model_copy(deep=True)) if WRITE.match(c.function)]
        missing = sorted({f"{c.function}.{k}={str(v)[:40]}" for c in writes for k, v in c.args.items()
                          for x in scalars(v) if norm(x) not in prompt and len(norm(x)) > 2})
        out.append(dict(suite=sn, user_task=uid, writes=[c.function for c in writes], not_in_prompt=missing, prompt=ut.PROMPT))
json.dump(out, open("user_authority.json", "w"), indent=1)
c = collections.Counter((o["suite"], "no writes" if not o["writes"] else ("all in prompt" if not o["not_in_prompt"] else "some from data")) for o in out)
for s in ["banking", "slack", "travel", "workspace"]:
    print(s, {k[1]: v for k, v in c.items() if k[0] == s})
