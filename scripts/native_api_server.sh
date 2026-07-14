#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=/opt/ngx-json-guard-api
ETC=/etc/ngx-json-guard-api
UNIT=ngx-json-guard-api.service
API_BIND_ADDRESS=${API_BIND_ADDRESS:-}
API_PORT=${API_PORT:-9100}
API_SERVER_LABEL=${API_SERVER_LABEL:-$(hostname -s)}
RESULTS_PARENT=${RESULTS_PARENT:-"$ROOT/artifacts/native-api"}

usage() {
    cat <<'EOF'
Usage: sudo API_BIND_ADDRESS=<private-ip> ./scripts/native_api_server.sh COMMAND

Commands:
  setup    Install and start the unprivileged streaming API service
  status   Show service status, health, and cumulative API metrics
  collect  Create a compressed API host/environment/metrics bundle

Bind to the DigitalOcean private VPC address. If a public address is used,
restrict TCP port 9100 to the WAF droplets with a cloud firewall.
EOF
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf 'native_api_server.sh must run through sudo or as root\n' >&2
        exit 2
    fi
}

load_installed_config() {
    if [ -z "$API_BIND_ADDRESS" ] && [ -r "$ETC/api.env" ]; then
        # shellcheck source=/dev/null
        . "$ETC/api.env"
    fi
}

validate() {
    if [[ ! "$API_SERVER_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        printf 'invalid API_SERVER_LABEL\n' >&2
        exit 2
    fi
    if ! [[ "$API_PORT" =~ ^[0-9]+$ ]] || [ "$API_PORT" -lt 1024 ] || [ "$API_PORT" -gt 65535 ]; then
        printf 'API_PORT must be between 1024 and 65535\n' >&2
        exit 2
    fi
    load_installed_config
    if [ -z "$API_BIND_ADDRESS" ]; then
        printf 'API_BIND_ADDRESS is required; use the droplet private IPv4 address\n' >&2
        exit 2
    fi
    python3 - "$API_BIND_ADDRESS" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4:
    raise SystemExit("only IPv4 bind addresses are supported")
if str(address) == "0.0.0.0" or (not address.is_private and not address.is_loopback):
    print("warning: API bind address is public; apply a restrictive cloud firewall", file=sys.stderr)
PY
    RESULTS_PARENT=$(realpath -m "$RESULTS_PARENT")
}

platform_check() {
    # shellcheck source=/dev/null
    . /etc/os-release
    if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
        printf 'Ubuntu 24.04 is required\n' >&2
        exit 2
    fi
    if [ "$(dpkg --print-architecture)" != amd64 ]; then
        printf 'amd64 is required\n' >&2
        exit 2
    fi
    if [ ! -e /sys/fs/cgroup/cgroup.controllers ] || [ "$(ps -p 1 -o comm=)" != systemd ]; then
        printf 'systemd with cgroup v2 is required\n' >&2
        exit 2
    fi
}

health_url() {
    local host=$API_BIND_ADDRESS
    if [ "$host" = 0.0.0.0 ]; then host=127.0.0.1; fi
    printf 'http://%s:%s' "$host" "$API_PORT"
}

wait_healthy() {
    local url
    url=$(health_url)
    for _ in $(seq 1 100); do
        if curl -fsS "$url/health" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    printf 'API service did not become healthy: %s\n' "$url" >&2
    return 2
}

setup() {
    platform_check
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl python3 sysstat zstd
    if ! id ngxjsonapi >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/ngx-json-guard-api \
            --shell /usr/sbin/nologin ngxjsonapi
    fi
    install -d -m 0755 "$PREFIX" "$ETC" /var/lib/ngx-json-guard-api
    install -Dm0755 "$ROOT/benchmark/native_body_sink.py" "$PREFIX/native_body_sink.py"
    printf 'API_BIND_ADDRESS=%s\nAPI_PORT=%s\n' "$API_BIND_ADDRESS" "$API_PORT" >"$ETC/api.env"
    chmod 0644 "$ETC/api.env"
    install -Dm0644 \
        "$ROOT/benchmark/native/api-systemd/ngx-json-guard-api.service" \
        "/etc/systemd/system/$UNIT"
    systemctl daemon-reload
    systemctl enable --now "$UNIT"
    systemctl restart "$UNIT"
    wait_healthy
    printf 'API ready: %s\n' "$(health_url)"
    printf 'WAF setup value: BACKEND_URL=%s\n' "$(health_url)"
}

status() {
    systemctl --no-pager --full status "$UNIT" || true
    printf '\nHealth:\n'
    curl -fsS "$(health_url)/health"; printf '\n'
    printf '\nMetrics:\n'
    curl -fsS "$(health_url)/metrics"; printf '\n'
}

cgroup_file() {
    local relative=$1 control
    control=$(systemctl show --property=ControlGroup --value "$UNIT")
    if [ -n "$control" ] && [ -r "/sys/fs/cgroup${control}/$relative" ]; then
        cat "/sys/fs/cgroup${control}/$relative"
    fi
}

collect() {
    local out name temporary archive owner
    out="$RESULTS_PARENT/${API_SERVER_LABEL}-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out/logs" "$out/configs"
    curl -fsS "$(health_url)/metrics" >"$out/metrics.json"
    journalctl --no-pager --output=short-iso --unit "$UNIT" >"$out/logs/journal.log"
    systemctl show "$UNIT" >"$out/logs/systemd-show.txt"
    cgroup_file cpu.stat >"$out/logs/cpu.stat"
    cgroup_file memory.current >"$out/logs/memory.current"
    cgroup_file memory.peak >"$out/logs/memory.peak"
    cgroup_file memory.events >"$out/logs/memory.events"
    cgroup_file io.stat >"$out/logs/io.stat"
    cgroup_file cpu.pressure >"$out/logs/cpu.pressure"
    cgroup_file memory.pressure >"$out/logs/memory.pressure"
    cgroup_file io.pressure >"$out/logs/io.pressure"
    lscpu --json >"$out/logs/lscpu.json"
    free -b >"$out/logs/free.txt"
    uname -a >"$out/logs/uname.txt"
    cp "$ETC/api.env" "$out/configs/api.env"
    cp "/etc/systemd/system/$UNIT" "$out/configs/$UNIT"
    cp "$ROOT/benchmark/native_body_sink.py" "$out/configs/native_body_sink.py"
    sha256sum "$PREFIX/native_body_sink.py" >"$out/configs/binary-source.sha256"
    cat >"$out/API_REPORT.md" <<EOF
# Native API Benchmark Host

- Label: `$API_SERVER_LABEL`
- Bind: `$API_BIND_ADDRESS:$API_PORT`
- Hostname: `$(hostname)`
- Kernel: `$(uname -r)`
- CPUs: `$(nproc)`
- Memory: `$(awk '/MemTotal/ {print $2 " " $3}' /proc/meminfo)`
- Service: `$UNIT`

The API streams request bodies into SHA-256 without retaining or parsing the
full body. Per-suite deltas are collected remotely by the WAF harness from the
`/metrics` endpoint.
EOF
    name=$(basename "$out")
    temporary=$(mktemp "$(dirname "$out")/.$name.XXXXXX.tar.zst")
    tar --zstd -cf "$temporary" -C "$(dirname "$out")" "$name"
    archive="$out/api-bundle.tar.zst"
    mv "$temporary" "$archive"
    (cd "$out" && sha256sum api-bundle.tar.zst >api-bundle.tar.zst.sha256)
    owner=${SUDO_USER:-root}
    chown -R "$owner":"$(id -gn "$owner")" "$out" 2>/dev/null || true
    printf 'API bundle: %s\n' "$archive"
}

main() {
    case "${1:-}" in
        help|-h|--help) usage; return ;;
    esac
    require_root
    validate
    case "${1:-}" in
        setup) setup ;;
        status) status ;;
        collect) collect ;;
        *) usage >&2; exit 2 ;;
    esac
}

main "$@"
