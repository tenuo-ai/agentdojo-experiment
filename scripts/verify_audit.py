"""Re-decide every call in a Tenuo arm's audit.jsonl, twice, and compare with the decision that was logged.

For each issuance the grant is re-derived from the prompt (adapter.issuer), then each call that reached the runtime
is checked (a) by analyze.outside_grant, plain Python with no Tenuo, and (b) by Tenuo, with a warrant re-minted
from that grant and validated on the same checked arguments enforce.py builds. A logged `allow` that either check
denies would be an enforcement failure; a logged `deny` that both allow would be an over-denial.

Usage: verify_audit.py RUN_ROOT   (e.g. results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2)
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites
from tenuo import SigningKey, Warrant

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapter import enforce, issuer  # noqa: E402
from scripts.analyze import RULES, outside_grant  # noqa: E402


def tenuo_decides(warrant_key, suite: str, function: str, args: dict) -> bool:
    bound, root = warrant_key
    spec = issuer.TARGETS[suite].get(function, {"targets": [], "side_effect": False})
    checked = {k: (enforce._checked(v, k in issuer.LIST_PARAMS) if k in spec["targets"] else v) for k, v in args.items()}
    try:
        return bool(bound.validate(function, checked, trusted_roots=[root]))
    except Exception:
        return False


def main() -> None:
    root = Path(sys.argv[1])
    suites = get_suites(root.name)
    directories = {sn: issuer.build_directory(sn, s.load_and_inject_default_environment({})) for sn, s in suites.items()}
    prompts = {(sn, uid): t.PROMPT for sn, s in suites.items() for uid, t in s.user_tasks.items()}
    prompts |= {(sn, iid): t.GOAL for sn, s in suites.items() for iid, t in s.injection_tasks.items()}
    issuer_key = SigningKey.generate()
    report = {}
    for arm, rule in RULES.items():
        path = root / arm / "audit.jsonl"
        if not path.exists():
            continue
        counts = collections.Counter()
        current = {}  # episode label -> (allowed, bound warrant); concurrent runs interleave lines
        for line in path.read_text().splitlines():
            r = json.loads(line)
            sn, uid = r["suite"], r["user_task"]
            key = (sn, uid, r["injection_task"])
            if r.get("event") == "issued":
                grant = issuer.issue(sn, prompts[(sn, uid)], directories[sn], rule)
                counts["issuances"] += 1
                counts["issuances whose logged grant differs"] += set(r["allowed_targets"]) != grant.allowed
                agent_key = SigningKey.generate()
                builder = Warrant.mint_builder()
                for tool, caps in grant.constraints.items():
                    builder = builder.capability(tool, **caps)
                warrant = builder.holder(agent_key.public_key).ttl(enforce.TTL_SECONDS).mint(issuer_key)
                current[key] = (grant.allowed, (warrant.bind(agent_key), issuer_key.public_key))
                continue
            allowed, warrant_key = current[key]
            python_allows = not outside_grant(sn, r["function"], r["args"], allowed)
            tenuo_allows = tenuo_decides(warrant_key, sn, r["function"], r["args"])
            logged_allows = r["decision"] == "allow"
            kind = "side-effecting" if r.get("side_effect") else "read-only"
            counts[f"{kind} calls"] += 1
            counts[f"{kind} logged allow"] += logged_allows
            counts[f"{kind} logged deny"] += not logged_allows
            counts["logged allow, plain check denies"] += logged_allows and not python_allows
            counts["logged allow, re-minted Tenuo denies"] += logged_allows and not tenuo_allows
            counts["logged deny, both checks allow"] += (not logged_allows) and python_allows and tenuo_allows
            counts["plain check and Tenuo disagree"] += python_allows != tenuo_allows
        report[arm] = dict(counts)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
