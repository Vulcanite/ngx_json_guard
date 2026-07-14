#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE="$ROOT/docker/docker-compose.api.yml"
OUT=${OUT:-"$ROOT/artifacts/waf-perf/$(date +%Y%m%d-%H%M%S)"}
PROFILE=${PROFILE:-benchmark}
WORKERS=${WORKERS:-4}
SMALL_REPEAT=${SMALL_REPEAT:-10}
LARGE_REPEAT=${LARGE_REPEAT:-1}
LARGE_MIB=${LARGE_MIB:-20}
BASE_URL=${BASE_URL:-http://127.0.0.1:8081}
WAF_CONFIG=${WAF_CONFIG:-main.conf}

case "$WAF_CONFIG" in
    main.conf|main-full.conf) ;;
    *) printf 'unsupported WAF_CONFIG: %s\n' "$WAF_CONFIG" >&2; exit 2 ;;
esac
export WAF_CONFIG

mkdir -p "$OUT"

# Recreate only the constrained WAF container so cgroup memory.peak and CPU
# counters describe this run. Upstream services remain warm and unchanged.
docker compose -f "$COMPOSE" up -d --no-deps --force-recreate ngx_json_guard_api_nginx

for _ in $(seq 1 60); do
    if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS "$BASE_URL/healthz" >/dev/null

docker inspect ngx_json_guard_api_nginx >"$OUT/container-inspect.json"
cp "$ROOT/docker/nginx.api.conf" "$OUT/nginx.api.conf"
cp "$ROOT/conf/modsecurity/$WAF_CONFIG" "$OUT/modsecurity.conf"
sha256sum \
    "$ROOT/docker/nginx.api.conf" \
    "$ROOT/conf/modsecurity/$WAF_CONFIG" \
    "$ROOT/ngx_http_json_guard_module.c" \
    "$ROOT/src/json_guard_parser.c" \
    >"$OUT/config-sha256.txt"

set +e
"$ROOT/scripts/waf_perf.py" \
    --url "$BASE_URL" \
    --profile "$PROFILE" \
    --workers "$WORKERS" \
    --small-repeat "$SMALL_REPEAT" \
    --large-repeat "$LARGE_REPEAT" \
    --large-mib "$LARGE_MIB" \
    --output-dir "$OUT" \
    "$@" 2>&1 | tee "$OUT/run.log"
status=${PIPESTATUS[0]}
set -e

docker exec ngx_json_guard_api_nginx cat /sys/fs/cgroup/cpu.stat \
    >"$OUT/cpu.stat"
docker exec ngx_json_guard_api_nginx cat /sys/fs/cgroup/memory.events \
    >"$OUT/memory.events"
docker exec ngx_json_guard_api_nginx cat /sys/fs/cgroup/memory.peak \
    >"$OUT/memory.peak"
docker logs --since 10m ngx_json_guard_api_nginx \
    >"$OUT/nginx.log" 2>&1 || true

printf 'report: %s\n' "$OUT/REPORT.md"
exit "$status"
