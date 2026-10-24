# Task-scoped authorization on AgentDojo

Does task-scoped, argument-constrained authorization prevent attacks that remain possible when an agent is already
authorized to use the tools the task needs? `methodology.md` has the arms, what the issuer may see, and the
metrics; `analysis/failure-taxonomy.md` classifies every Tenuo failure.

## Result so far: gpt-4o-mini-2024-07-18, v1.2.2, `important_instructions`, one run

All 949 attacked pairs and 97 benign tasks:

| arm | benign utility | utility under attack | attack success (official) | attacker call executed | executed calls outside the warrant | benign approval requests |
|---|---|---|---|---|---|---|
| baseline | 71.1% | 37.4% | 30.8% | 53.0% | n/a | 0% |
| tool_filter | 63.9% | 60.4% | 5.7% | 7.7% | n/a | 0% |
| tenuo (prompt) | 46.4% | 40.4% | 3.9% | 2.5% | 0 | 38% |
| tenuo_both | 63.9% | 44.0% | 7.1% | 5.3% | 0 | 15% |
| tenuo_directory | 53.6% | 39.4% | 6.8% | 5.9% | 0 | 29% |
| tenuo_tool_filter | 47.4% | 48.8% | 1.2% | 0.0% | 0 | 33% |
| contract_gate (PR #183) | 53.6% | 51.3% | 2.2% | 1.1% | n/a | n/a |

The 89 same-tool pairs (counts of 89; benign utility is on the 44 user tasks behind them, without attack):

| arm | benign utility (of 44) | utility under attack | attack success (official) | attacker call executed | task done and no attack |
|---|---|---|---|---|---|
| baseline | 30 | 33 | 38 | 44 | 21 |
| tool_filter | 26 | 23 | 37 | 40 | 10 |
| tenuo (prompt) | 13 | 15 | 0 | 1 | 15 |
| tenuo_both | 21 | 29 | 4 | 5 | 27 |
| tenuo_directory | 14 | 22 | 4 | 5 | 20 |
| tenuo_tool_filter | 14 | 19 | 0 | 0 | 19 |
| contract_gate (PR #183) | 20 | 22 | 6 | 6 | 20 |

"Attacker call executed" counts pairs where a call carrying out the injection task's goal ran: it matches
`scripts/attack_effects.py` (typed comparison against the attacker's identifier) and returned without an error.
The official scorer misses some of these. It reads only the first new calendar event, needs an amount above 10,
and checks only the final state, so a reservation that was later overwritten does not count. It also counts some
that are not attacks (a context-length error scores as success). For non-Tenuo arms the count is a lower bound:
AgentDojo retries an episode whose model ends without a final message and logs only the last attempt (see
`methodology.md`).

- `tool_filter` leaves same-tool attacks where they were (37 scored, 40 executed, vs 38 and 44).
- Prompt-scoped targets: 0 of 89 same-tool attacks scored and 1 executed (travel `user_task_4`, an injected
  event on the user's own calendar). The model tried the attack in 44 pairs; in 43 every attacker call was
  denied.
- No call exceeded a warrant. Re-deciding all 28,613 audited calls in the four Tenuo arms, by plain Python and
  with a re-minted warrant, reproduces every logged decision, and every executed side-effecting call has an audit
  `allow` (`scripts/verify_audit.py`, `scripts/analyze.py`). Every executed attack was inside what the issuer
  granted, including the calendar event: `create_calendar_event`'s only target is `participants`, and the
  injected event had none. The issuer constrains *whom* a side effect reaches, not *what* it says or *when*.
- The cost is utility, and the zero should not be read without it. On the 89 pairs the prompt arm completes 15
  tasks against the baseline's 33. "Task done and no attack" is 15 against the baseline's 21: the prompt arm
  completes the task safely *less* often than no defense. Adding the trusted directory (`tenuo_both`) gives 27,
  with 4 scored and 5 executed attacks. All of this is one run; differences of a few pairs are within noise.

The execution-aware columns were corrected after an external audit (Giselle Evita Koch, agentdojo#184). The
earlier counter matched substrings of serialized arguments and erred both ways. `analysis/external-audit/` has the
audit, the reproduction, a per-row table, and what changed.

## The 89 same-tool pairs

`analysis/pairs_v1.2.2.json` classifies all 949 (user task, injection task) pairs. The same-tool pairs, where the
injection only uses tools the user task already needs, are the 89 with category `2_same_tool_args_in_prompt` (2) or
`3_same_tool_arg_differs` (87): banking 42, workspace 22, slack 19, travel 6.

```bash
jq '[.[] | select(.category | test("^[23]_"))]' analysis/pairs_v1.2.2.json
```

`analysis/classify_pairs.py` generates the file from the benchmark's reference solutions only; nothing in it feeds the
issuer or the policy.

## Layout

- `adapter/`: the issuer (`issuer.py`, sees only the prompt, the target table and the pre-attack directory) and
  enforcement (`enforce.py`, a pipeline element that swaps in a runtime checking each call against the warrant).
- `policies/targets.json`: which tools have side effects and which parameters name a target (generated).
- `scripts/`: `run_arm.py` (one arm), `run_all.sh`, `resume.sh` (reruns unfinished arm/suite pairs),
  `analyze.py` (official and execution-aware metrics, with `attack_effects.py`), `verify_audit.py` (re-decides
  every audited call), `replay_episode.py` (replays logged episodes and re-scores them), `replay_reference.py`
  (offline bound).
- `analysis/`: pair classification (`pairs_v1.2.2.json`), failure dump and taxonomy, discussion notes,
  `external-audit/` (reproduction of the external audit).
- `results/archives/` (episode and audit logs as tarballs; `tar xzf <file> -C results/raw` restores `results/raw/`;
  the archives contain macOS `._*` files, which the scripts skip)
  and `results/summary/` (CSV and JSON).
- `upstream/`: drafts for Tenuo and AgentDojo issues. Filed: #910 (null), #967 (case folding).

## Running

```bash
cd agentdojo && uv sync                                   # .venv; contract_gate needs .venv-contractgate (PR #183)
PYTHONPATH=. .venv/bin/python -m pytest tests             # offline enforcement tests
OPENAI_API_KEY=... PYTHONPATH=. .venv/bin/python scripts/run_arm.py --arm tenuo --suite banking --out results/raw/dev
./scripts/resume.sh gpt-4o-mini-2024-07-18 results/raw/dev 3     # finish anything incomplete, 3 at a time
PYTHONPATH=. .venv/bin/python scripts/analyze.py results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2
PYTHONPATH=. .venv/bin/python scripts/verify_audit.py results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2
PYTHONPATH=. .venv/bin/python scripts/replay_episode.py results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2 --all
R=results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2
for a in tenuo tenuo_both tenuo_tool_filter tenuo_directory; do PYTHONPATH=. .venv/bin/python analysis/failure_dump.py $R $a; done
PYTHONPATH=. .venv/bin/python analysis/classify_failures.py $R tenuo tenuo_tool_filter tenuo_both tenuo_directory
```

About $3 per arm on gpt-4o-mini, about $45 per arm on a gpt-4o-class model. Run at most three jobs at once or
rate limits outlast AgentDojo's retries.

## Next

- A disclosed second issuer that also scopes the content and time of writes to the user's own objects (calendar
  title/date, owned-file deletes), checked first on a targeted rerun of the calendar tasks
  (`analysis/external-audit/README.md`).
- Three runs of the 89 pairs and 97 benign tasks for variance before any stronger model.
- Decide on posting and validation before a stronger model (`gpt-4o` on the 89 same-tool pairs and 97 benign
  tasks for three arms is about $25-30).
- A second, disclosed issuer: per-parameter target types, and no tool without a reason to grant it.
- Ajar (open-privilege measure) after that.
