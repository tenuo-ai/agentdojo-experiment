#!/bin/bash
# Run every arm x suite in parallel. Usage: run_all.sh MODEL VERSION OUT
set -u
MODEL=${1:-gpt-4o-mini-2024-07-18}; VERSION=${2:-v1.2.2}; OUT=${3:-results/raw}
cd "$(dirname "$0")/.."
mkdir -p "$OUT/logs"
for arm in baseline tool_filter tenuo tenuo_both tenuo_tool_filter; do
  for suite in banking slack travel workspace; do
    PYTHONPATH=. .venv/bin/python scripts/run_arm.py --arm $arm --suite $suite --model "$MODEL" --version "$VERSION" \
      --out "$OUT" > "$OUT/logs/$arm-$suite.log" 2>&1 &
  done
done
wait
grep -h -E "^(baseline|tool_filter|tenuo)" "$OUT"/logs/*.log
