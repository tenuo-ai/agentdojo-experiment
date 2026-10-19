"""Compare candidate issuer rules offline. Reference solutions are used only to MEASURE a rule, never to build it.

Every rule grants every tool. Read tools are unconstrained; each side-effecting tool's target argument must be in an
allowed set. Rules differ only in where that set comes from:
  prompt     : identifiers written in the user's prompt
  directory  : the pre-episode trusted directory (known payees, contacts, workspace users and channels, own files/events)
  both       : prompt or directory
"""
import collections, json, re
from agentdojo.task_suite.load_suites import get_suites
from classify_pairs import WRITE, OVERRIDES, scalars, norm
from agentdojo.functions_runtime import FunctionCall

TARGET = {  # per-suite application policy, from tool signatures: which argument names the thing acted on
    "send_money": "recipient", "schedule_transaction": "recipient", "update_scheduled_transaction": "recipient",
    "send_direct_message": "recipient", "send_channel_message": "channel", "add_user_to_channel": "user",
    "invite_user_to_slack": "user", "remove_user_from_slack": "user", "post_webpage": "url", "get_webpage": "url",
    "send_email": "recipients", "share_file": "email", "delete_file": "file_id", "delete_email": "email_id",
    "create_calendar_event": "participants", "add_calendar_event_participants": "participants",
    "reserve_hotel": "hotel", "reserve_restaurant": "restaurant", "reserve_car_rental": "company",
}

def directory(suite, env):
    d = set()
    if suite == "banking":
        a = env.bank_account
        d |= {t.recipient for t in a.transactions + a.scheduled_transactions if t.sender in ("me", a.iban)}
    if suite == "slack":
        d |= set(env.slack.users) | set(env.slack.channels)
    if suite in ("workspace", "travel"):
        inbox = env.inbox
        d |= {c.email for c in inbox.contact_list} | {inbox.account_email}
    if suite == "workspace":
        d |= set(env.cloud_drive.files) | set(inbox.emails)  # own file and email ids
    return {norm(x) for x in d}

def allowed(rule, value, prompt, direc):
    v = norm(value)
    in_prompt = len(v) > 2 and v in prompt
    return {"prompt": in_prompt, "directory": v in direc, "both": in_prompt or v in direc}[rule]

def call_ok(rule, call, prompt, direc):
    arg = TARGET.get(call.function)
    if not arg or not WRITE.match(call.function):
        return True
    vals = list(scalars(call.args.get(arg)))
    return bool(vals) and all(allowed(rule, x, prompt, direc) for x in vals)

res = collections.defaultdict(collections.Counter)
for sn, suite in get_suites("v1.2.2").items():
    env = suite.load_and_inject_default_environment({})
    direc = directory(sn, env)
    inj = {}
    for iid, t in suite.injection_tasks.items():
        c = list(t.ground_truth(env.model_copy(deep=True))) or [FunctionCall(function=f, args=a) for f, a in OVERRIDES.get((sn, iid), [])]
        inj[iid] = c
    pairs = {(r["user_task"], r["injection_task"]): r["category"] for r in json.load(open("pairs_v1.2.2.json")) if r["suite"] == sn}
    for uid, ut in suite.user_tasks.items():
        prompt = ut.PROMPT.lower()
        ucalls = list(ut.ground_truth(env.model_copy(deep=True)))
        for rule in ("prompt", "directory", "both"):
            res[rule]["user_tasks"] += 1
            res[rule]["benign_blocked"] += not all(call_ok(rule, c, prompt, direc) for c in ucalls)
            for iid, ic in inj.items():
                cat = pairs[(uid, iid)]
                if cat.startswith("4"):
                    continue
                key = "same_tool" if cat[0] in "23" else "new_tool"
                res[rule][key] += 1
                res[rule][key + "_blocked"] += not all(call_ok(rule, c, prompt, direc) for c in ic)
print(f"{'rule':10} {'benign tasks blocked':>22} {'same-tool attacks blocked':>27} {'new-tool attacks blocked':>26}")
for rule, c in res.items():
    print(f"{rule:10} {c['benign_blocked']:>12}/{c['user_tasks']:<9} {c['same_tool_blocked']:>15}/{c['same_tool']:<11} {c['new_tool_blocked']:>14}/{c['new_tool']:<11}")
