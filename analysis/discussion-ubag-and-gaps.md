# For discussion: UBAG, and gaps vs design choices

## Do we need UBAG?

Not for the hypothesis. The question is tool-level vs task+argument authority. UBAG is a third thing:
relationship-scoped destination allow-lists (known payees, contacts, workspace users), not tied to the task, plus a
provenance check and an optional behavioral layer, decided by a hosted service.

Options:

1. **Ask the authors for gateway access** and run their arm as configured. Most faithful. Outward-facing: we would
   be telling another defense's authors we are benchmarking them. Daniel's call on timing.
2. **Cite their published numbers** (v1, gpt-4o-mini and gemini-2.5-flash, run logs in PR #190) with their own
   caveat that baselines drifted (their gpt-4o-mini baseline ASR 43% vs 27% published). Cheap, but different
   version, time and harness, so not a like-for-like row.
3. **Run the relationship-scoped rule ourselves** as a directory-only Tenuo arm, labelled as "relationship-scoped
   rule (UBAG's allow-list derivation, our implementation)", never as UBAG. It isolates the variable we care about
   (task-scoped vs relationship-scoped targets) without their provenance or behavioral layers. About $3 on the dev
   model.

Recommendation: 3 now, 2 in related work, 1 only if we decide to publish a head-to-head table.

## Gap or design choice?

| Finding | Verdict | Why | Possible response |
|---|---|---|---|
| No constraint matches `null` (optional args) | **Gap** in expressiveness | Closed world (unnamed args denied, named args required) is deliberate. But "this value or absent" is still an explicit, closed statement; today it cannot be written, so adapters substitute a sentinel and the checked value stops matching the executed one. Same issue blocked Hermes' optional `terminal` args. | `Null()`/`Exact(None)` usable in `AnyOf`, or `optional=True` per argument. Small, compatible. |
| Exact, case-sensitive matching | **Design choice** | Equality is the only domain-free semantics. Case rules are per type: hostnames fold, email local parts technically don't, Slack handles depend on the product. A global `casefold` flag would encode one domain's rule everywhere. | Typed constraints where the semantics are standard (`UrlPattern` already normalizes hosts; an email/host type could), and the existing pattern: normalize once, check and execute the normalized value (as `tenuo.process` does with `realpath`). |
| Targets chosen from data ("pay the bill in this file", "the channel with the most users") | **Not a constraint gap; an issuance question** | A warrant can pin any value or pattern once someone decides it. The hard part is who decides, when, and from what trusted input. Tenuo separates issuance from enforcement on purpose. | Three issuance patterns to document or build: approval when the target is not established (approval gates exist); re-issuance after a trusted read; an issuer that computes the target from trusted state ("most users" is computable before the attack, but turning the sentence into that query needs language understanding). |
| Which tools a task needs ("pay the bill" -> `send_money`; no-target tools like `update_password`) | **Issuance question** | Granting or omitting a tool is trivial to express. Deciding from natural language is the problem, and a deterministic rule written by someone who has read the benchmark would be tuned to it. | Same as above; the AgentDojo combination arm (tool_filter + Tenuo) shows the split: an LLM can choose tools, a warrant pins arguments. |
| Same target, malicious content (phishing link to Alice, to today's meeting participants) | **Out of scope by design** | Authority is "who/what may be acted on". The content is the attack. `Not(Regex(...))` or CEL could forbid URLs in a body, but the issuer has no principled way to know which content is allowed. | Say so plainly in the write-up; it is the residual class for any action-authorization defense. |
| Signatures and delegation not exercised | **Benchmark limit** | AgentDojo has one agent and no cross-process verifier, so a plain allow-list from the same issuer scores the same. | State it; a multi-agent benchmark (or Ajar's open-privilege measure) is where delegation matters. |

## What this suggests for the product

The constraint language held up: everything the issuer could decide, Tenuo could express, except null. The work
AgentDojo exposes is in issuance: turning a request into authority, and handling authority that depends on data.
That is where the team should decide how much Tenuo owns (templates, an issuer SDK, approval flows, an LLM planner
with a deterministic enforcer) versus leaves to integrators.
