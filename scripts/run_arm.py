"""Run one arm of the experiment with AgentDojo's own benchmark functions and scorer.

Arms (identical model, system message, attack, tool loop; only the defense differs):
  baseline          AgentDojo with no defense
  tool_filter       AgentDojo's tool_filter defense (an LLM picks the tools for the task)
  tenuo             Tenuo, prompt-only targets, every tool granted
  tenuo_both        Tenuo, targets from the prompt or the trusted directory
  tenuo_tool_filter tool_filter picks the tools, then Tenuo (prompt-only targets) constrains their arguments
  tenuo_directory   targets limited to the trusted directory, not the prompt: a relationship-scoped rule, our
                    implementation of UBAG's allow-list derivation (not UBAG itself: no provenance or behavioral layer)
  contract_gate     ContractGate (AgentDojo PR #183, head 24a0711423f1), as its authors configure it;
                    run from .venv-contractgate, which installs AgentDojo from that PR

Outputs: AgentDojo's per-episode JSON logs and a results.json with its official metrics, plus audit.jsonl
(every call that reached the runtime, with the decision) for the Tenuo arms.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import Logger, OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from adapter import enforce, issuer

def guard_scorer_crashes(suite, log_path: Path) -> None:
    """Issue #188: some utility checks index state that a blocked call never created and raise KeyError instead of
    returning False. Score that as a utility failure and record it. Applied identically to every arm."""
    for task in suite.user_tasks.values():
        original = task.utility

        def utility(*a, _original=original, _id=task.ID, **k):
            try:
                return _original(*a, **k)
            except KeyError as exc:
                with log_path.open("a") as f:
                    f.write(json.dumps({"suite": suite.name, "user_task": _id, "error": f"KeyError: {exc}"}) + "\n")
                return False

        object.__setattr__(task, "utility", utility)


def guard_unparseable_tool_calls(log_path: Path) -> None:
    """The model sometimes returns a tool call whose JSON arguments are truncated, and AgentDojo's OpenAI wrapper
    raises, aborting the whole suite. Treat it as the model ending its turn with no tool call, and record it.
    Applied identically to every arm; it only changes episodes that would otherwise crash."""
    from agentdojo.agent_pipeline.llms import openai_llm
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

    original = openai_llm._openai_to_assistant_message
    if getattr(original, "_guarded", False):
        return

    def convert(message):
        try:
            return original(message)
        except json.JSONDecodeError as exc:
            ctx = getattr(Logger.get(), "context", {}) or {}
            with log_path.open("a") as f:
                f.write(json.dumps({"suite": ctx.get("suite_name"), "user_task": ctx.get("user_task_id"),
                                    "injection_task": ctx.get("injection_task_id"),
                                    "error": f"JSONDecodeError: {exc}"}) + "\n")
            return ChatAssistantMessage(role="assistant", tool_calls=None,
                                        content=[text_content_block_from_string(message.content or "")])

    convert._guarded = True
    openai_llm._openai_to_assistant_message = convert


ARMS = ("baseline", "tool_filter", "tenuo", "tenuo_both", "tenuo_tool_filter", "tenuo_directory", "contract_gate")


def build(arm: str, model: str, suite_name: str, suite, audit: enforce.AuditLog) -> AgentPipeline:
    defense = {"tool_filter": "tool_filter", "tenuo_tool_filter": "tool_filter", "contract_gate": "contract_gate"}.get(arm)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=model, model_id=None, defense=defense, system_message_name=None,
                       system_message=load_system_message(None))
    )
    if arm.startswith("tenuo"):
        directory = issuer.build_directory(suite_name, suite.load_and_inject_default_environment({}))
        rule = {"tenuo_both": "both", "tenuo_directory": "directory"}.get(arm, "prompt")
        element = enforce.TenuoAuthorization(suite_name, directory, rule, audit)
        # After the system message, the query and (if present) the tool filter; before the first model call.
        index = 3 if defense else 2
        pipeline.elements = [*pipeline.elements[:index], element, *pipeline.elements[index:]]
    pipeline.name = f"{model}-{arm}"
    return pipeline


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--arm", choices=ARMS, required=True)
    p.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    p.add_argument("--version", default="v1.2.2")
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--suite", action="append", default=None)
    p.add_argument("--user-task", action="append", default=None)
    p.add_argument("--injection-task", action="append", default=None)
    p.add_argument("--out", type=Path, default=Path("results/raw"))
    p.add_argument("--no-benign", action="store_true")
    args = p.parse_args()

    run_dir = args.out / args.model / args.version / args.arm
    run_dir.mkdir(parents=True, exist_ok=True)
    audit = enforce.AuditLog(run_dir / "audit.jsonl" if args.arm.startswith("tenuo") else None)
    guard_unparseable_tool_calls(run_dir / "harness_errors.jsonl")
    summary = {"arm": args.arm, "model": args.model, "version": args.version, "attack": args.attack,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "suites": {}}
    for suite_name in args.suite or ["banking", "slack", "travel", "workspace"]:
        suite = get_suite(args.version, suite_name)
        guard_scorer_crashes(suite, run_dir / "scorer_errors.jsonl")
        pipeline = build(args.arm, args.model, suite_name, suite, audit)
        with OutputLogger(str(run_dir), live=None):
            benign = None
            if not args.no_benign:
                benign = benchmark_suite_without_injections(pipeline, suite, run_dir, force_rerun=False,
                                                            user_tasks=args.user_task, benchmark_version=args.version)
            attack = load_attack(args.attack, suite, pipeline)
            attacked = benchmark_suite_with_injections(pipeline, suite, attack, run_dir, force_rerun=False,
                                                       user_tasks=args.user_task, injection_tasks=args.injection_task,
                                                       verbose=False, benchmark_version=args.version)
        summary["suites"][suite_name] = {
            "benign_utility": {f"{k[0]}": v for k, v in (benign["utility_results"] if benign else {}).items()},
            "utility_under_attack": {f"{k[0]}|{k[1]}": v for k, v in attacked["utility_results"].items()},
            "attack_success": {f"{k[0]}|{k[1]}": v for k, v in attacked["security_results"].items()},
        }
        s = summary["suites"][suite_name]
        n = max(len(s["attack_success"]), 1)
        print(f"{args.arm} {suite_name}: benign utility {sum(s['benign_utility'].values())}/{len(s['benign_utility'])}"
              f"  utility under attack {sum(s['utility_under_attack'].values())}/{n}"
              f"  attack success (official) {sum(s['attack_success'].values())}/{n}")
        (run_dir / f"results_{suite_name}.json").write_text(json.dumps({**summary, "suites": {suite_name: s},
                                                                     "finished": time.strftime("%Y-%m-%dT%H:%M:%S")},
                                                                    indent=1))


if __name__ == "__main__":
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    main()
