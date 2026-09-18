# Benchmark fixtures

Small committed samples so parser numbers can be regenerated without the
gitignored  `artifacts/` tree (that tree is multi-gigabyte run output, not
source).

| File | What it is |
|---|---|
| `small_object.json` | ~50 B object; use this to check per-request parser cost |

Larger bodies are generated on demand (they do not belong in git):

```sh
# 100 KiB / 1 MiB / 10 MiB valid JSON into /tmp
python3 scripts/gen_large_json.py --size-mb 0.1 --output /tmp/jg_0.1m.json
python3 scripts/gen_large_json.py --size-mb 1 --output /tmp/jg_1m.json
python3 scripts/gen_large_json.py --size-mb 10 --output /tmp/jg_10m.json

# Standalone parser micro-benchmark (median + p99)
make tests/bench_json_guard_repeat
./tests/bench_json_guard_repeat benchmark/fixtures/small_object.json 15
./tests/bench_json_guard_repeat /tmp/jg_1m.json 15
```

End-to-end NGINX / ModSecurity / Coraza numbers still come from
`make waf-perf`, `make waf-high-concurrency`, and `make cross-waf-full`.
Those write under `artifacts/` and are not required to confirm the
parser itself.
