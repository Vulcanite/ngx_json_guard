#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE="$ROOT/benchmark/docker-compose.yml"
ENGINE_FILE="$ROOT/benchmark/engines.json"
RESULTS_ROOT=${RESULTS_ROOT:-"$ROOT/artifacts/cross-waf/$(date +%Y%m%d-%H%M%S)"}
PAYLOAD_DIR=${PAYLOAD_DIR:-"$ROOT/artifacts/cross-waf/payloads"}
MODE=${MODE:-quick}
ENGINES=${ENGINES:-"nginx-baseline nginx-guard nginx-modsecurity-processor nginx-guard-modsecurity-processor nginx-modsecurity-crs nginx-guard-modsecurity-crs coraza-processor coraza-crs"}
TIMEOUT=${TIMEOUT:-300}

case "$MODE" in
    smoke|quick|full) ;;
    *) printf 'MODE must be smoke, quick, or full\n' >&2; exit 2 ;;
esac

mkdir -p "$RESULTS_ROOT" "$PAYLOAD_DIR"
python3 "$ROOT/scripts/cross_waf_bench.py" generate --payload-dir "$PAYLOAD_DIR"

docker compose -f "$COMPOSE" up -d --build json_api xml_api form_api web_app

engine_field() {
    python3 - "$ENGINE_FILE" "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])
PY
}

wait_healthy() {
    local url=$1
    for _ in $(seq 1 90); do
        if curl -fsS "$url/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    printf 'target did not become healthy: %s\n' "$url" >&2
    return 1
}

run_one_suite() {
    local engine=$1 suite=$2 workers=$3
    local out="$RESULTS_ROOT/$engine/${suite}-w${workers}"
    local extra=()
    case "$MODE" in
        smoke)
            extra+=(--max-repeat 1 --quick)
            if [ "$suite" = correctness ]; then
                extra+=(--case-regex '^(valid_|malformed_|invalid_|unpaired_|trailing_|duplicate_|depth_10[01]|wide_array_10001|key_length_4097|number_length_257|tokens_100001|attack_sqli_small|fp_apostrophe)')
            fi
            ;;
        quick)
            extra+=(--max-repeat 2 --quick)
            ;;
        full)
            extra+=(--warmup)
            ;;
    esac
    mkdir -p "$out"
    set +e
    python3 "$ROOT/scripts/cross_waf_bench.py" run \
        --engine "$engine" \
        --suite "$suite" \
        --payload-dir "$PAYLOAD_DIR" \
        --output-dir "$out" \
        --workers "$workers" \
        --timeout "$TIMEOUT" \
        "${extra[@]}" 2>&1 | tee "$out/run.log"
    local status=${PIPESTATUS[0]}
    set -e
    return "$status"
}

start_target() {
    docker compose -f "$COMPOSE" --profile nginx --profile coraza rm -sf nginx_waf coraza_waf >/dev/null 2>&1 || true
    if [ "$family" = nginx ]; then
        BENCH_NGINX_PROFILE="$nginx_profile" BENCH_RULE_PROFILE="$rule_profile" \
            docker compose -f "$COMPOSE" --profile nginx up -d --no-deps --force-recreate "$service"
    else
        BENCH_RULE_PROFILE="$rule_profile" \
            docker compose -f "$COMPOSE" --profile coraza up -d --no-deps --force-recreate "$service"
    fi
    wait_healthy "$base_url"
}

overall=0
for engine in $ENGINES; do
    family=$(engine_field "$engine" family)
    service=$(engine_field "$engine" service)
    container=$(engine_field "$engine" container)
    base_url=$(engine_field "$engine" base_url)
    rule_profile=$(engine_field "$engine" rule_profile)
    crs=$(engine_field "$engine" crs)

    if [ "$family" = nginx ]; then
        nginx_profile=$(engine_field "$engine" nginx_profile)
    fi
    start_target

    engine_out="$RESULTS_ROOT/$engine"
    mkdir -p "$engine_out"
    docker inspect "$container" >"$engine_out/container-inspect.json"
    docker image inspect "$(docker inspect -f '{{.Image}}' "$container")" >"$engine_out/image-inspect.json"
    cp "$ENGINE_FILE" "$engine_out/engines.json"
    if [ "$family" = nginx ]; then
        cp "$ROOT/benchmark/nginx.conf" "$engine_out/server.conf"
        cp "$ROOT/benchmark/nginx/$nginx_profile" "$engine_out/profile.conf"
        cp "$ROOT/benchmark/modsecurity/$rule_profile" "$engine_out/rules.conf"
    else
        cp "$ROOT/benchmark/Caddyfile" "$engine_out/server.conf"
        cp "$ROOT/benchmark/coraza/$rule_profile" "$engine_out/rules.conf"
    fi

    if ! run_one_suite "$engine" correctness 1; then overall=1; fi
    if [ "$MODE" != smoke ]; then
        if [ "$crs" = True ]; then
            start_target
            if ! run_one_suite "$engine" crs 1; then overall=1; fi
            start_target
            if ! run_one_suite "$engine" mixed 4; then overall=1; fi
        else
            start_target
            if ! run_one_suite "$engine" processor 1; then overall=1; fi
            if [ "$MODE" = full ]; then
                start_target
                if ! run_one_suite "$engine" processor 2; then overall=1; fi
                start_target
                if ! run_one_suite "$engine" processor 4; then overall=1; fi
            fi
        fi
    fi
    docker logs "$container" >"$engine_out/container.log" 2>&1 || true
done

python3 "$ROOT/scripts/cross_waf_bench.py" report --results-root "$RESULTS_ROOT"
printf 'comparison: %s\n' "$RESULTS_ROOT/COMPARISON.md"
exit "$overall"
