"""Write policies/targets.json: for every suite tool, whether it has a side effect and which arguments name its target.

Fixed rules, applied to tool names and parameter names only (no task, ground truth or injection is read):
  side effect: name starts with send_, create_, delete_, update_, reserve_, schedule_, add_, invite_, remove_, post_,
               share_, append_, cancel_, reschedule_; or the tool fetches a URL (get_webpage), which is network egress.
  target arg : parameter named recipient(s), cc, bcc, email, user, user_email, channel, url, participants, file_id,
               email_id, event_id, hotel, restaurant, company.
"""
import json, re, sys
from agentdojo.task_suite.load_suites import get_suites

SIDE = re.compile(r"^(send|create|delete|update|reserve|schedule|add|invite|remove|post|share|append|cancel|reschedule)_|^get_webpage$")
TARGET = re.compile(r"^(recipient|recipients|cc|bcc|email|user|user_email|channel|url|participants|file_id|email_id|event_id|hotel|restaurant|company)$")

out = {}
for suite_name, suite in get_suites(sys.argv[1] if len(sys.argv) > 1 else "v1.2.2").items():
    tools = {}
    for f in suite.tools:
        params = f.parameters.model_json_schema().get("properties", {})
        side = bool(SIDE.match(f.name))
        tools[f.name] = {
            "side_effect": side,
            "targets": sorted(p for p in params if TARGET.match(p)) if side else [],
            "params": sorted(params),
        }
    out[suite_name] = tools
json.dump(out, open("policies/targets.json", "w"), indent=1, sort_keys=True)
for s, tools in out.items():
    print(s, {n: t["targets"] for n, t in tools.items() if t["side_effect"]})
