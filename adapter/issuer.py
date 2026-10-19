"""Warrant issuer for one AgentDojo episode.

What the issuer sees, and nothing else:
  - the user's prompt (the `query` AgentDojo passes to the pipeline);
  - policies/targets.json, built from tool and parameter names only;
  - a directory taken from the suite's environment loaded with its benign default injection values, i.e. the
    deployment as it stood before any attacker content arrived.

It never imports injection tasks, ground truth, scorers or the logger's episode context
(tests/test_issuer_inputs.py checks this).

Rules (see methodology.md):
  prompt     every tool is granted; each side-effecting tool's target arguments may only take values the prompt
             states, either literally (IBAN, email, URL) or by naming a directory entry (a Slack user, a contact,
             a file, an event, a hotel). Anything else is denied and counted as an approval request.
  directory  target values may be anything in the directory, whether or not the prompt names it.
  both       the union of the two.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tenuo import OneOf, Subset, Wildcard

TARGETS = json.loads((Path(__file__).resolve().parent.parent / "policies" / "targets.json").read_text())
LIST_PARAMS = {"recipients", "cc", "bcc", "participants"}
NO_TARGET = ""  # an absent optional target (None, or no list) is checked as this value: "no new party"

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/[\w./-]*)?", re.I)


def canon(value: Any) -> str:
    return str(value).strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")


@dataclass
class Directory:
    """Names the deployment knows, mapped to the identifiers tools take."""

    names: dict[str, set[str]] = field(default_factory=dict)  # lowercase name -> identifiers
    relationships: set[str] = field(default_factory=set)  # identifiers with an existing relationship

    def add(self, name: Any, ident: Any, relationship: bool = True) -> None:
        if name is None or ident is None or not str(name).strip():
            return
        self.names.setdefault(str(name).strip().lower(), set()).add(str(ident))
        if relationship:
            self.relationships.add(str(ident))


def build_directory(suite_name: str, env: Any) -> Directory:
    d = Directory()
    if suite_name == "banking":
        account = env.bank_account
        for t in [*account.transactions, *account.scheduled_transactions]:
            if t.sender in ("me", account.iban):
                d.relationships.add(t.recipient)
    if suite_name == "slack":
        for user in env.slack.users:
            d.add(user, user)
        for channel in env.slack.channels:
            d.add(channel, channel)
    if suite_name in ("workspace", "travel"):
        inbox = env.inbox
        for c in inbox.contact_list:
            d.add(c.name, c.email)
            d.add(c.email, c.email)
        d.add(inbox.account_email, inbox.account_email)
        for e in inbox.emails.values():
            d.add(e.subject, e.id_)
        for ev in env.calendar.events.values():
            d.add(ev.title, ev.id_)
    if suite_name == "workspace":
        for f in env.cloud_drive.files.values():
            d.add(f.filename, f.id_)
    if suite_name == "travel":  # vendors are not relationships: naming one is the only way to authorize it
        for h in env.hotels.hotel_list:
            d.add(h.name, h.name, relationship=False)
        for r in env.restaurants.restaurant_list:
            d.add(r.name, r.name, relationship=False)
        for c in env.car_rental.company_list:
            d.add(c.name, c.name, relationship=False)
    return d


def named_in_prompt(prompt: str, directory: Directory) -> set[str]:
    """Identifiers the prompt states literally or names through the directory."""
    found = set(_IBAN.findall(prompt)) | {m.lower() for m in _EMAIL.findall(prompt)}
    found |= {canon(m) for m in _URL.findall(prompt) if "@" not in m}
    lowered = prompt.lower()
    for name, idents in directory.names.items():
        if len(name) >= 3 and re.search(r"(?<![\w@.])" + re.escape(name) + r"(?![\w@])", lowered):
            found |= idents
    return found


@dataclass
class Grant:
    """What one episode's warrant allows, before it is minted."""

    allowed: set[str]
    constraints: dict[str, dict[str, Any]]


def issue(suite_name: str, prompt: str, directory: Directory, rule: str = "prompt") -> Grant:
    if rule not in ("prompt", "directory", "both"):
        raise ValueError(rule)
    allowed: set[str] = set()
    if rule in ("prompt", "both"):
        allowed |= named_in_prompt(prompt, directory)
    if rule in ("directory", "both"):
        allowed |= directory.relationships
    canonical = sorted({canon(v) for v in allowed})
    constraints: dict[str, dict[str, Any]] = {}
    for tool, spec in TARGETS[suite_name].items():
        caps: dict[str, Any] = {}
        for param in spec["params"]:
            if param not in spec["targets"]:
                caps[param] = Wildcard()
            elif param in LIST_PARAMS:
                caps[param] = Subset(canonical)
            else:
                caps[param] = OneOf([NO_TARGET, *canonical])
        constraints[tool] = caps
    return Grant(allowed=set(canonical), constraints=constraints)
