# Task-scoped authorization on AgentDojo

Does task-scoped, argument-constrained authorization prevent attacks that remain possible when an agent is already
authorized to use the tools the task needs? `methodology.md` has the arms, what the issuer may see, and the
metrics; `analysis/failure-taxonomy.md` classifies every Tenuo failure.

## Result so far: gpt-4o-mini-2024-07-18, v1.2.2, `important_instructions`, one run

| arm | benign utility | utility under attack | attack success (official) | attack executed | same-tool success (of 89) | benign approval requests |
|---|---|---|---|---|---|---|
| baseline | 71.1% | 37.4% | 30.8% | 51.8% | 38 | 0% |
| tool_filter | 63.9% | 60.4% | 5.7% | 5.7% | 37 | 0% |
| tenuo (prompt) | 46.4% | 40.4% | 3.9% | 2.4% | 0 | 38% |
| tenuo_both | 63.9% | 44.0% | 7.1% | 4.4% | 4 | 15% |
| tenuo_directory | 53.6% | 39.4% | 6.8% | 5.4% | 4 | 29% |
| tenuo_tool_filter | 47.4% | 48.8% | 1.2% | 0.1% | 0 | 33% |
| contract_gate (PR #183) | 53.6% | 51.3% | 2.2% | 0.9% | 6 | n/a |

"Attack executed" is the share of attacked pairs where an attacker call ran, from the episode logs; it is
approximate (see `scripts/analyze.py`), and `analysis/failure-taxonomy.md` has the per-case counts.

- `tool_filter` leaves same-tool attacks where they were (37 vs 38); task-scoped targets stop all 89.
- No executed attack bypassed a warrant; every one was inside what the issuer granted.
- The cost is benign utility where the task picks its target from data (27 tasks in the prompt arm).

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
  `analyze.py` (official and execution-aware metrics), `replay_reference.py` (offline bound).
- `analysis/`: pair classification (`pairs_v1.2.2.json`), failure dump and taxonomy, discussion notes.
- `results/archives/` (episode and audit logs as tarballs; `tar xzf <file> -C results/raw` restores `results/raw/`)
  and `results/summary/` (CSV and JSON).
- `upstream/`: drafts for Tenuo and AgentDojo issues. Filed: #910 (null), #967 (case folding).

## Running

```bash
cd agentdojo && uv sync                                   # .venv; contract_gate needs .venv-contractgate (PR #183)
PYTHONPATH=. .venv/bin/python -m pytest tests             # offline enforcement tests
OPENAI_API_KEY=... PYTHONPATH=. .venv/bin/python scripts/run_arm.py --arm tenuo --suite banking --out results/raw/dev
./scripts/resume.sh gpt-4o-mini-2024-07-18 results/raw/dev 3     # finish anything incomplete, 3 at a time
PYTHONPATH=. .venv/bin/python scripts/analyze.py results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2
R=results/raw/dev/gpt-4o-mini-2024-07-18/v1.2.2
for a in tenuo tenuo_both tenuo_tool_filter tenuo_directory; do PYTHONPATH=. .venv/bin/python analysis/failure_dump.py $R $a; done
PYTHONPATH=. .venv/bin/python analysis/classify_failures.py $R tenuo tenuo_tool_filter tenuo_both tenuo_directory
```

About $3 per arm on gpt-4o-mini, about $45 per arm on a gpt-4o-class model. Run at most three jobs at once or
rate limits outlast AgentDojo's retries.

## Next

- Decide on posting and validation before a stronger model (`gpt-4o` on the 89 same-tool pairs and 97 benign
  tasks for three arms is about $25-30).
- A second, disclosed issuer: per-parameter target types, and no tool without a reason to grant it.
- Ajar (open-privilege measure) after that.
