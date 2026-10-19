"""Enforcement at the last step before a tool body runs.

`TenuoAuthorization` is a pipeline element. At the start of each episode it asks the issuer for a grant, mints a
warrant from a fixed issuer key to a per-episode agent key, and replaces the runtime with one whose functions check
that warrant. FunctionsRuntime.run_function resolves nested calls, validates arguments and adds environment
dependencies, then calls the function; the check runs inside that call, on the validated public arguments, so every
path that executes a tool (including nested calls) passes through it. Dependencies are never shown to the check.

A denied or failed check raises; run_function reports it to the model as an ordinary tool error and the body does
not run. The tool receives exactly the arguments run_function passed; identifiers are compared case-insensitively
(see issuer.canon), which is the only difference between the checked and executed values.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.logging import Logger
from agentdojo.types import ChatMessage
from tenuo import SigningKey, Warrant

from . import issuer as issuer_mod

ISSUER_KEY = SigningKey.generate()  # the operator's key; trusted root for every episode
TTL_SECONDS = 1800


class ToolAuthorizationDenied(Exception):
    """The call is outside the authority granted for this request. It was not executed."""


class AuditLog:
    """One JSON line per tool call that reaches the runtime. Episode labels come from AgentDojo's logger and are
    used only to join records with results; they are never passed to the issuer or the check."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, **record: Any) -> None:
        if self.path is None:
            return
        ctx = getattr(Logger.get(), "context", {}) or {}
        record = {
            "suite": ctx.get("suite_name"),
            "user_task": ctx.get("user_task_id"),
            "injection_task": ctx.get("injection_task_id"),
            "ts": time.time(),
            **record,
        }
        with self._lock, self.path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")


def _checked(value: Any, is_list: bool) -> Any:
    if is_list:
        return [issuer_mod.canon(v) for v in (value or [])]
    return issuer_mod.NO_TARGET if value is None else issuer_mod.canon(value)


def authorizing_runtime(
    runtime: FunctionsRuntime, warrant: Warrant, agent_key: SigningKey, targets: dict, audit: AuditLog
) -> FunctionsRuntime:
    bound = warrant.bind(agent_key)
    roots = [ISSUER_KEY.public_key]
    wrapped = {}
    for name, function in runtime.functions.items():
        spec = targets.get(name, {"targets": [], "side_effect": False})
        deps = set(function.dependencies)
        original = function.run

        def run(*args: Any, _name=name, _spec=spec, _deps=deps, _original=original, **kwargs: Any) -> Any:
            public = {k: v for k, v in kwargs.items() if k not in _deps}
            checked = {
                k: (_checked(v, k in issuer_mod.LIST_PARAMS) if k in _spec["targets"] else v) for k, v in public.items()
            }
            try:
                result = bound.validate(_name, checked, trusted_roots=roots)
                allowed, reason = bool(result), (result.reason or "")
            except Exception as exc:  # fail closed
                allowed, reason = False, f"authorization error: {type(exc).__name__}: {exc}"
            audit.write(
                function=_name, args=public, side_effect=_spec["side_effect"], decision="allow" if allowed else "deny",
                reason=reason.split(" Debug at:")[0][:300], executed=allowed,
            )
            if not allowed:
                raise ToolAuthorizationDenied(
                    f"`{_name}` with these arguments is outside the authority granted for this request, so it was "
                    "not executed. It needs the user's approval."
                )
            return _original(*args, **kwargs)

        wrapped[name] = function.model_copy(update={"run": run})
    new = FunctionsRuntime([])
    new.functions = wrapped
    return new


class TenuoAuthorization(BasePipelineElement):
    """Issue a warrant from the user's request, then enforce it for the rest of the episode."""

    name = "tenuo"

    def __init__(self, suite_name: str, directory: issuer_mod.Directory, rule: str, audit: AuditLog) -> None:
        self.suite_name = suite_name
        self.directory = directory
        self.rule = rule
        self.audit = audit
        self.targets = issuer_mod.TARGETS[suite_name]

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        grant = issuer_mod.issue(self.suite_name, query, self.directory, self.rule)
        agent_key = SigningKey.generate()
        builder = Warrant.mint_builder()
        for tool, caps in grant.constraints.items():
            builder = builder.capability(tool, **caps)
        warrant = builder.holder(agent_key.public_key).ttl(TTL_SECONDS).mint(ISSUER_KEY)
        self.audit.write(event="issued", rule=self.rule, allowed_targets=sorted(grant.allowed))
        return query, authorizing_runtime(runtime, warrant, agent_key, self.targets, self.audit), env, messages, extra_args
