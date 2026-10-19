#!/bin/bash
# Resume every (arm, suite) without a results file, at most $3 at a time. Finished episodes are skipped by AgentDojo.
set -u
MODEL=${1:-gpt-4o-mini-2024-07-18}; OUT=${2:-results/raw/dev}; JOBS=${3:-3}; VERSION=v1.2.2
cd "$(dirname "$0")/.."
todo=()
for arm in baseline tool_filter tenuo tenuo_both tenuo_tool_filter tenuo_directory contract_gate; do
  for suite in banking slack travel workspace; do
    [ -f "$OUT/$MODEL/$VERSION/$arm/results_$suite.json" ] && continue
    pgrep -f -- "--arm $arm --suite $suite" >/dev/null && continue
    todo+=("$arm $suite")
  done
done
printf '%s\n' "${todo[@]}" | xargs -P "$JOBS" -L 1 bash -c '
  py=.venv/bin/python; [ "$0" = contract_gate ] && py=.venv-contractgate/bin/python
  PYTHONPATH=. $py scripts/run_arm.py --arm "$0" --suite "$1" --model '"$MODEL"' --version '"$VERSION"' --out '"$OUT"' >> '"$OUT"'/logs/"$0"-"$1".log 2>&1'
for f in "$OUT"/logs/*.log; do grep -h -E "^(baseline|tool_filter|tenuo|contract_gate)" "$f" | tail -1; done
