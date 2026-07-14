#!/usr/bin/env bash
# Benchmark the standalone streaming JSON parser.
#
# Usage:
#   ./scripts/bench_parser.sh [path-to-json]
#   ./scripts/bench_parser.sh --generate 10
#
# Measures wall time and, when available, max RSS via /usr/bin/time -v.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BENCH_BIN="$ROOT/tests/bench_json_guard_parser"
PARSER_SRC="$ROOT/src/json_guard_parser.c"
BENCH_SRC="$ROOT/tests/bench_json_guard_parser.c"

build_bench() {
  cc -Wall -Wextra -Werror -O2 -I"$ROOT/src" \
    "$BENCH_SRC" "$PARSER_SRC" -o "$BENCH_BIN"
}

JSON_PATH=""
if [[ "${1:-}" == "--generate" ]]; then
  MB="${2:-10}"
  JSON_PATH="/tmp/jg_bench_${MB}mb.json"
  python3 "$ROOT/scripts/gen_large_json.py" --size-mb "$MB" --output "$JSON_PATH"
elif [[ $# -ge 1 ]]; then
  JSON_PATH="$1"
else
  JSON_PATH="/tmp/jg_bench_10mb.json"
  if [[ ! -f "$JSON_PATH" ]]; then
    python3 "$ROOT/scripts/gen_large_json.py" --size-mb 10 --output "$JSON_PATH"
  fi
fi

if [[ ! -f "$JSON_PATH" ]]; then
  echo "JSON file not found: $JSON_PATH" >&2
  exit 1
fi

build_bench

BYTES=$(wc -c < "$JSON_PATH" | tr -d ' ')
echo "File: $JSON_PATH ($BYTES bytes)"
echo "Binary: $BENCH_BIN"
echo

if command -v /usr/bin/time >/dev/null 2>&1; then
  # GNU time -v for max RSS; fall back to plain timing if not GNU.
  if /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v "$BENCH_BIN" "$JSON_PATH"
  else
    /usr/bin/time -p "$BENCH_BIN" "$JSON_PATH"
  fi
else
  START=$(date +%s.%N)
  "$BENCH_BIN" "$JSON_PATH"
  END=$(date +%s.%N)
  python3 - <<PY
start=float("$START"); end=float("$END")
print(f"elapsed_sec={end-start:.6f}")
PY
fi
