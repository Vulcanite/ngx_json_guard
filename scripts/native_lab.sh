#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=/opt/ngx-json-guard
ETC=/etc/ngx-json-guard
BUILD="$PREFIX/build"
TOOLCHAIN="$PREFIX/toolchain"
ENGINE_TEMPLATE="$ROOT/benchmark/native/engines.json"
ENGINE_FILE=${ENGINE_FILE:-"$ETC/engines.json"}
PAYLOAD_DIR=${PAYLOAD_DIR:-/var/lib/ngx-json-guard/payloads}
RESULTS_PARENT=${RESULTS_PARENT:-"$ROOT/artifacts/native"}
SERVER_LABEL=${SERVER_LABEL:-$(hostname -s)}
TIMEOUT=${TIMEOUT:-300}
BUILD_JOBS=${BUILD_JOBS:-2}
FORCE_REBUILD=${FORCE_REBUILD:-0}
ALLOW_SWAP=${ALLOW_SWAP:-0}
ENGINES=${ENGINES:-"nginx-baseline nginx-guard nginx-modsecurity-processor nginx-guard-modsecurity-processor nginx-modsecurity-crs nginx-guard-modsecurity-crs coraza-processor coraza-crs"}
VERSIONS_FILE="$ROOT/benchmark/native/versions.env"
LAST_RUN_FILE="$RESULTS_PARENT/.last-run"
RUN_DIR=${RUN_DIR:-}
FINDINGS=0
MONITOR_PIDS=()
BACKEND_URL=${BACKEND_URL:-}
if [ -z "$BACKEND_URL" ] && [ -r "$ETC/lab.env" ]; then
    # shellcheck source=/dev/null
    . "$ETC/lab.env"
fi
BACKEND_URL=${BACKEND_URL:-http://127.0.0.1:9100}
BACKEND_HOST=
BACKEND_PORT=
BACKEND_LOCAL=0
BACKEND_PUBLIC=0

# shellcheck source=/dev/null
. "$VERSIONS_FILE"

usage() {
    cat <<'EOF'
Usage: sudo [SERVER_LABEL=name] ./scripts/native_lab.sh COMMAND

Commands:
  setup   Validate Ubuntu 24.04, build pinned native binaries, install services
  smoke   Run the focused correctness matrix
  quick   Run the representative <=20 MiB matrix
  full    Run warm-ups, planned repetitions, and concurrency 1/2/4
  large   Run one 50/100 MiB and 64/128 MiB boundary supplement
  bundle  Bundle the most recent run without payload bodies
  all     Setup, run the full and large matrices, then create one bundle
EOF
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf 'native_lab.sh must run through sudo or as root\n' >&2
        exit 2
    fi
}

validate_inputs() {
    if [[ ! "$SERVER_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        printf 'SERVER_LABEL must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}\n' >&2
        exit 2
    fi
    RESULTS_PARENT=$(realpath -m "$RESULTS_PARENT")
    LAST_RUN_FILE="$RESULTS_PARENT/.last-run"
    if [ -n "$RUN_DIR" ]; then
        RUN_DIR=$(realpath -m "$RUN_DIR")
        case "$RUN_DIR/" in
            "$RESULTS_PARENT"/*) ;;
            *) printf 'RUN_DIR must be below RESULTS_PARENT\n' >&2; exit 2 ;;
        esac
    fi
    configure_backend
}

configure_backend() {
    local parsed
    parsed=$(python3 - "$BACKEND_URL" <<'PY'
import ipaddress, re, sys
from urllib.parse import urlsplit

value = urlsplit(sys.argv[1])
if value.scheme != "http" or not value.hostname or value.username or value.password:
    raise SystemExit("BACKEND_URL must be an unauthenticated http://host:port URL")
if value.path not in ("", "/") or value.query or value.fragment:
    raise SystemExit("BACKEND_URL must not contain a path, query, or fragment")
host = value.hostname
if ":" in host:
    raise SystemExit("IPv6 backend literals are not supported by the native templates")
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise SystemExit("BACKEND_URL host contains unsupported characters")
port = value.port or 80
local = host == "localhost" or host.startswith("127.")
public = False
try:
    public = not ipaddress.ip_address(host).is_private
except ValueError:
    public = not local
print(host, port, int(local), int(public))
PY
    ) || exit 2
    read -r BACKEND_HOST BACKEND_PORT BACKEND_LOCAL BACKEND_PUBLIC <<<"$parsed"
    BACKEND_URL="http://$BACKEND_HOST:$BACKEND_PORT"
    if [ "$BACKEND_PUBLIC" -eq 1 ]; then
        printf 'warning: BACKEND_URL may be public; restrict port %s to the WAF hosts\n' \
            "$BACKEND_PORT" >&2
    fi
}

preflight() {
    if [ ! -r /etc/os-release ]; then
        printf '/etc/os-release is missing\n' >&2
        return 2
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
        printf 'Ubuntu 24.04 is required; found %s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
        return 2
    fi
    if [ "$(dpkg --print-architecture)" != amd64 ]; then
        printf 'amd64 is required\n' >&2
        return 2
    fi
    if [ ! -e /sys/fs/cgroup/cgroup.controllers ] || [ "$(ps -p 1 -o comm=)" != systemd ]; then
        printf 'systemd with cgroup v2 is required\n' >&2
        return 2
    fi
    if [ "$ALLOW_SWAP" != 1 ] && [ "$(swapon --noheadings 2>/dev/null | wc -l)" -ne 0 ]; then
        printf 'active swap is not allowed; disable it or set ALLOW_SWAP=1\n' >&2
        return 2
    fi
    available=$(df -PB1 "$ROOT" | awk 'NR==2 {print $4}')
    if [ "$available" -lt $((10 * 1024 * 1024 * 1024)) ]; then
        printf 'at least 10 GiB free disk is required\n' >&2
        return 2
    fi
}

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates curl g++ git jq \
        libcurl4-openssl-dev liblmdb-dev libpcre2-dev libssl-dev \
        libtool libxml2-dev libyajl-dev make pkg-config python3 sysstat \
        uuid-dev wget zlib1g-dev zstd
}

source_fingerprint() {
    {
        cat "$VERSIONS_FILE"
        find "$ROOT/src" -type f -print0 | sort -z | xargs -0 sha256sum
        sha256sum "$ROOT/config" "$ROOT/ngx_http_json_guard_module.c"
    } | sha256sum | awk '{print $1}'
}

clone_ref() {
    local url=$1 ref=$2 destination=$3 expected_commit=$4 actual_commit
    rm -rf "$destination"
    git clone --depth 1 --branch "$ref" "$url" "$destination"
    actual_commit=$(git -C "$destination" rev-parse HEAD)
    if [ "$actual_commit" != "$expected_commit" ]; then
        printf '%s resolved to %s, expected %s\n' "$ref" "$actual_commit" "$expected_commit" >&2
        return 2
    fi
}

build_native() {
    local fingerprint marker
    fingerprint=$(source_fingerprint)
    marker="$PREFIX/.build-fingerprint"
    if [ "$FORCE_REBUILD" != 1 ] \
        && [ -x "$PREFIX/nginx/sbin/nginx" ] && [ -x "$PREFIX/bin/caddy" ] \
        && [ -r "$PREFIX/BUILD_MANIFEST.txt" ] \
        && [ -r "$marker" ] && [ "$(cat "$marker")" = "$fingerprint" ]; then
        printf 'native binaries already match fingerprint %s\n' "$fingerprint"
        return
    fi

    install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$BUILD" "$TOOLCHAIN"
    rm -f "$marker"
    rm -rf "$BUILD"/*
    install -d -m 0755 "$BUILD/ngx_json_guard"
    cp "$ROOT/config" "$ROOT/ngx_http_json_guard_module.c" "$BUILD/ngx_json_guard/"
    cp -a "$ROOT/src" "$BUILD/ngx_json_guard/src"

    clone_ref https://github.com/owasp-modsecurity/ModSecurity \
        "$MODSECURITY_REF" "$BUILD/ModSecurity" "$MODSECURITY_COMMIT"
    (
        cd "$BUILD/ModSecurity"
        git submodule update --init --recursive --depth 1
        ./build.sh
        ./configure --prefix="$PREFIX/modsecurity"
        make -j"$BUILD_JOBS"
        make install
    )

    clone_ref https://github.com/owasp-modsecurity/ModSecurity-nginx \
        "$MODSECURITY_NGINX_REF" "$BUILD/ModSecurity-nginx" "$MODSECURITY_NGINX_COMMIT"
    clone_ref https://github.com/coreruleset/coreruleset \
        "$CRS_REF" "$BUILD/coreruleset" "$CRS_COMMIT"
    cp "$BUILD/coreruleset/crs-setup.conf.example" "$BUILD/coreruleset/crs-setup.conf"

    nginx_archive="$BUILD/nginx-$NGINX_VERSION.tar.gz"
    curl -fsSL "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" -o "$nginx_archive"
    printf '%s  %s\n' "$NGINX_SHA256" "$nginx_archive" | sha256sum -c -
    tar -C "$BUILD" -xzf "$nginx_archive"
    (
        cd "$BUILD/nginx-$NGINX_VERSION"
        export PKG_CONFIG_PATH="$PREFIX/modsecurity/lib/pkgconfig:$PREFIX/modsecurity/lib64/pkgconfig"
        export MODSECURITY_INC="$PREFIX/modsecurity/include"
        if [ -e "$PREFIX/modsecurity/lib/libmodsecurity.so" ]; then
            export MODSECURITY_LIB="$PREFIX/modsecurity/lib"
        else
            export MODSECURITY_LIB="$PREFIX/modsecurity/lib64"
        fi
        ./configure \
            --prefix="$PREFIX/nginx" \
            --modules-path="$PREFIX/nginx/modules" \
            --with-compat \
            --with-http_ssl_module \
            --with-http_realip_module \
            --with-http_stub_status_module \
            --with-cc-opt="-I$PREFIX/modsecurity/include" \
            --with-ld-opt="-L$PREFIX/modsecurity/lib -L$PREFIX/modsecurity/lib64 -Wl,-rpath,$PREFIX/modsecurity/lib -Wl,-rpath,$PREFIX/modsecurity/lib64" \
            --add-dynamic-module="$BUILD/ModSecurity-nginx" \
            --add-dynamic-module="$BUILD/ngx_json_guard"
        make -j"$BUILD_JOBS"
        make install
        install -Dm0755 objs/ngx_http_modsecurity_module.so \
            "$PREFIX/nginx/modules/ngx_http_modsecurity_module.so"
        install -Dm0755 objs/ngx_http_json_guard_module.so \
            "$PREFIX/nginx/modules/ngx_http_json_guard_module.so"
    )

    rm -rf "$PREFIX/crs"
    cp -a "$BUILD/coreruleset" "$PREFIX/crs"
    install -Dm0644 "$BUILD/ModSecurity/unicode.mapping" \
        "$PREFIX/modsecurity/share/unicode.mapping"

    go_archive="$BUILD/go$GO_VERSION.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" -o "$go_archive"
    printf '%s  %s\n' "$GO_LINUX_AMD64_SHA256" "$go_archive" | sha256sum -c -
    rm -rf "$TOOLCHAIN/go" "$TOOLCHAIN/bin" "$TOOLCHAIN/gopath"
    tar -C "$TOOLCHAIN" -xzf "$go_archive"
    install -d -m 0755 "$TOOLCHAIN/bin" "$TOOLCHAIN/gopath"
    export PATH="$TOOLCHAIN/go/bin:$TOOLCHAIN/bin:$PATH"
    export GOBIN="$TOOLCHAIN/bin"
    export GOPATH="$TOOLCHAIN/gopath"
    export GOMODCACHE="$TOOLCHAIN/gopath/pkg/mod"
    export GOTOOLCHAIN=local
    export GOFLAGS=-p=2
    export GOMAXPROCS=2
    go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION"
    xcaddy build "$CADDY_VERSION" \
        --output "$PREFIX/bin/caddy" \
        --with "github.com/corazawaf/coraza-caddy/v2@$CORAZA_CADDY_REF"

    build_info=$($PREFIX/bin/caddy build-info)
    printf '%s\n' "$build_info" | grep -F "github.com/corazawaf/coraza/v3" | grep -F "$CORAZA_VERSION" >/dev/null
    printf '%s\n' "$build_info" | grep -F "github.com/corazawaf/coraza-coreruleset/v4" | grep -F "$CORAZA_CRS_VERSION" >/dev/null
    printf '%s\n' "$build_info" | grep -F "${CORAZA_CADDY_REF:0:12}" >/dev/null

    {
        printf 'fingerprint=%s\n' "$fingerprint"
        printf 'nginx_sha256=%s\n' "$(sha256sum "$nginx_archive" | awk '{print $1}')"
        printf 'go_sha256=%s\n' "$(sha256sum "$go_archive" | awk '{print $1}')"
        printf 'modsecurity_commit=%s\n' "$(git -C "$BUILD/ModSecurity" rev-parse HEAD)"
        printf 'modsecurity_nginx_commit=%s\n' "$(git -C "$BUILD/ModSecurity-nginx" rev-parse HEAD)"
        printf 'crs_commit=%s\n' "$(git -C "$BUILD/coreruleset" rev-parse HEAD)"
        printf 'nginx_binary_sha256=%s\n' "$(sha256sum "$PREFIX/nginx/sbin/nginx" | awk '{print $1}')"
        printf 'caddy_binary_sha256=%s\n' "$(sha256sum "$PREFIX/bin/caddy" | awk '{print $1}')"
        printf 'cc_version=%s\n' "$(cc --version | head -1)"
        printf 'cxx_version=%s\n' "$(c++ --version | head -1)"
        printf 'go_version=%s\n' "$(go version)"
        printf 'xcaddy_version=%s\n' "$(xcaddy version 2>&1 || true)"
        printf '\n%s\n' "$build_info"
    } >"$PREFIX/BUILD_MANIFEST.txt"
    printf '%s\n' "$fingerprint" >"$marker"
}

render_modsecurity_rules() {
    local source=$1 destination=$2
    sed \
        -e "s#/etc/nginx/modsec/unicode.mapping#$PREFIX/modsecurity/share/unicode.mapping#g" \
        -e "s#/etc/nginx/modsec/crs#$PREFIX/crs#g" \
        -e 's#/var/log/modsec/audit.log#/var/log/ngx-json-guard/modsecurity-audit.log#g' \
        "$source" >"$destination"
}

install_runtime() {
    if ! id ngxjsonbench >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/ngx-json-guard \
            --shell /usr/sbin/nologin ngxjsonbench
    fi
    install -d -m 0755 \
        "$ETC/nginx/profiles" "$ETC/modsecurity/profiles" \
        "$ETC/coraza/profiles" /var/lib/ngx-json-guard/client_body_temp \
        /var/lib/ngx-json-guard/proxy_temp /var/lib/ngx-json-guard/caddy \
        "$PAYLOAD_DIR" /var/log/ngx-json-guard "$PREFIX/benchmark"

    install -Dm0755 "$ROOT/benchmark/native_body_sink.py" \
        "$PREFIX/benchmark/native_body_sink.py"
    sed -e "s/__BACKEND_HOST__/$BACKEND_HOST/g" -e "s/__BACKEND_PORT__/$BACKEND_PORT/g" \
        "$ROOT/benchmark/native/nginx.conf" >"$ETC/nginx/nginx.conf"
    sed -e "s/__BACKEND_HOST__/$BACKEND_HOST/g" -e "s/__BACKEND_PORT__/$BACKEND_PORT/g" \
        "$ROOT/benchmark/native/Caddyfile" >"$ETC/coraza/Caddyfile"
    for profile in "$ROOT"/benchmark/nginx/*.conf; do
        install -Dm0644 "$profile" "$ETC/nginx/profiles/$(basename "$profile")"
    done
    render_modsecurity_rules "$ROOT/benchmark/modsecurity/processor.conf" \
        "$ETC/modsecurity/profiles/processor.conf"
    render_modsecurity_rules "$ROOT/benchmark/modsecurity/full-crs.conf" \
        "$ETC/modsecurity/profiles/full-crs.conf"
    sed 's#/var/log/coraza/audit.log#/var/log/ngx-json-guard/coraza-audit.log#g' \
        "$ROOT/benchmark/coraza/processor.conf" >"$ETC/coraza/profiles/processor.conf"
    sed 's#/var/log/coraza/audit.log#/var/log/ngx-json-guard/coraza-audit.log#g' \
        "$ROOT/benchmark/coraza/full-crs.conf" >"$ETC/coraza/profiles/full-crs.conf"

    cp "$ETC/nginx/profiles/off.conf" "$ETC/nginx/profile.conf"
    cp "$ETC/modsecurity/profiles/processor.conf" "$ETC/modsecurity/active.conf"
    cp "$ETC/coraza/profiles/processor.conf" "$ETC/coraza/active.conf"
    printf 'BACKEND_URL=%s\n' "$BACKEND_URL" >"$ETC/lab.env"
    install -d -m 0755 "$(dirname "$ENGINE_FILE")"
    python3 - "$ENGINE_TEMPLATE" "$ENGINE_FILE" "$BACKEND_URL" "$BACKEND_LOCAL" <<'PY'
import json, sys
source, destination, backend_url, local = sys.argv[1:]
engines = json.load(open(source))
for engine in engines.values():
    engine["backend_metrics_url"] = backend_url.rstrip("/") + "/metrics"
    engine["backend_units"] = ["ngx-json-guard-backend.service"] if local == "1" else []
with open(destination, "w") as stream:
    json.dump(engines, stream, indent=2)
    stream.write("\n")
PY

    for unit in "$ROOT"/benchmark/native/systemd/*.service; do
        install -Dm0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
    done
    chown -R ngxjsonbench:ngxjsonbench /var/lib/ngx-json-guard /var/log/ngx-json-guard
    chmod 0755 "$PREFIX" "$PREFIX/nginx" "$PREFIX/bin"
    systemctl daemon-reload
    if [ "$BACKEND_LOCAL" -eq 1 ]; then
        systemctl enable --now ngx-json-guard-backend.service
    else
        systemctl disable --now ngx-json-guard-backend.service 2>/dev/null || true
    fi
    systemctl stop ngx-json-guard-nginx.service ngx-json-guard-coraza.service 2>/dev/null || true
    if LD_LIBRARY_PATH="$PREFIX/modsecurity/lib:$PREFIX/modsecurity/lib64" \
        ldd "$PREFIX/nginx/modules/ngx_http_modsecurity_module.so" | grep -q 'not found'; then
        printf 'ModSecurity NGINX module has unresolved shared libraries\n' >&2
        return 2
    fi
    LD_LIBRARY_PATH="$PREFIX/modsecurity/lib:$PREFIX/modsecurity/lib64" \
        "$PREFIX/nginx/sbin/nginx" -t -c "$ETC/nginx/nginx.conf"
    "$PREFIX/bin/caddy" validate --config "$ETC/coraza/Caddyfile" --adapter caddyfile
}

setup() {
    require_root
    preflight
    install_packages
    make -C "$ROOT" clean test test-asan
    build_native
    install_runtime
    native_integration_check
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$ROOT/tests" 2>/dev/null || true
    fi
    printf 'native setup complete\n'
}

ensure_setup() {
    local installed_backend
    require_root
    preflight
    if [ ! -x "$PREFIX/nginx/sbin/nginx" ] || [ ! -x "$PREFIX/bin/caddy" ]; then
        printf 'native binaries are missing; run setup first\n' >&2
        return 2
    fi
    if [ ! -r "$ENGINE_FILE" ]; then
        printf 'installed native engine descriptor is missing; run setup again\n' >&2
        return 2
    fi
    installed_backend=$(sed -n 's/^BACKEND_URL=//p' "$ETC/lab.env")
    if [ "$installed_backend" != "$BACKEND_URL" ]; then
        printf 'BACKEND_URL differs from installed configuration; rerun setup\n' >&2
        return 2
    fi
    if [ "$BACKEND_LOCAL" -eq 1 ]; then
        systemctl start ngx-json-guard-backend.service
    fi
    wait_backend
}

engine_field() {
    python3 - "$ENGINE_FILE" "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))[sys.argv[2]]
for key in sys.argv[3].split('.'):
    value = value[key]
print(value)
PY
}

new_run_dir() {
    if [ -n "$RUN_DIR" ]; then
        mkdir -p "$RUN_DIR"
    else
        RUN_DIR="$RESULTS_PARENT/${SERVER_LABEL}-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$RUN_DIR"
    fi
    mkdir -p "$RUN_DIR/profiles" "$RUN_DIR/logs" "$RUN_DIR/configs"
    mkdir -p "$RESULTS_PARENT"
    printf '%s\n' "$RUN_DIR" >"$LAST_RUN_FILE"
}

wait_healthy() {
    local url=$1
    for _ in $(seq 1 120); do
        if curl -fsS "$url/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    printf 'target did not become healthy: %s\n' "$url" >&2
    return 2
}

wait_backend() {
    for _ in $(seq 1 60); do
        if curl -fsS "$BACKEND_URL/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    printf 'native backend did not become healthy\n' >&2
    return 2
}

stop_targets() {
    systemctl stop ngx-json-guard-nginx.service ngx-json-guard-coraza.service 2>/dev/null || true
    systemctl reset-failed ngx-json-guard-nginx.service ngx-json-guard-coraza.service 2>/dev/null || true
}

wait_cgroup_removed() {
    local unit=$1 control
    control=$(systemctl show --property=ControlGroup --value "$unit" 2>/dev/null || true)
    if [ -z "$control" ]; then
        return 0
    fi
    for _ in $(seq 1 100); do
        if [ ! -e "/sys/fs/cgroup${control}" ]; then
            return 0
        fi
        sleep 0.1
    done
    printf 'cgroup was not removed for %s: %s\n' "$unit" "$control" >&2
    return 2
}

cleanup_on_exit() {
    stop_monitors 2>/dev/null || true
    stop_targets 2>/dev/null || true
}

start_target() {
    local engine=$1
    local family unit base_url rule_profile nginx_profile
    family=$(engine_field "$engine" family)
    unit=$(engine_field "$engine" runtime.unit)
    base_url=$(engine_field "$engine" base_url)
    rule_profile=$(engine_field "$engine" rule_profile)
    if [ "$family" = nginx ]; then
        nginx_profile=$(engine_field "$engine" nginx_profile)
    fi

    stop_targets
    wait_cgroup_removed ngx-json-guard-nginx.service
    wait_cgroup_removed ngx-json-guard-coraza.service
    if [ "$BACKEND_LOCAL" -eq 1 ]; then
        systemctl stop ngx-json-guard-backend.service
        wait_cgroup_removed ngx-json-guard-backend.service
        systemctl start ngx-json-guard-backend.service
    else
        systemctl stop ngx-json-guard-backend.service 2>/dev/null || true
    fi
    wait_backend
    : >/var/log/ngx-json-guard/nginx-access.log
    : >/var/log/ngx-json-guard/nginx-error.log
    : >/var/log/ngx-json-guard/modsecurity-audit.log
    : >/var/log/ngx-json-guard/coraza-audit.log
    chown ngxjsonbench:ngxjsonbench /var/log/ngx-json-guard/*.log

    if [ "$family" = nginx ]; then
        cp "$ETC/nginx/profiles/$nginx_profile" "$ETC/nginx/profile.conf"
        cp "$ETC/modsecurity/profiles/$rule_profile" "$ETC/modsecurity/active.conf"
    else
        cp "$ETC/coraza/profiles/$rule_profile" "$ETC/coraza/active.conf"
    fi
    systemctl start "$unit"
    wait_healthy "$base_url"
    sleep 1
}

native_integration_check() {
    local work status expected actual guard_header
    work=$(mktemp -d /tmp/ngx-json-guard-native-check.XXXXXX)
    printf '%s' '{"message":"native preservation check"}' >"$work/valid.json"
    expected=$(sha256sum "$work/valid.json" | awk '{print $1}')

    start_target nginx-guard-modsecurity-crs
    status=$(curl -sS -D "$work/headers" -o "$work/response" -w '%{http_code}' \
        -H 'Content-Type: application/json' --data-binary @"$work/valid.json" \
        http://127.0.0.1:8091/json/ingest)
    actual=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$work/response")
    if [ "$status" != 200 ] || [ "$actual" != "$expected" ]; then
        printf 'native NGINX body-preservation check failed\n' >&2
        return 2
    fi
    status=$(curl -sS -D "$work/headers" -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' --data-binary '{"a":1,}' \
        http://127.0.0.1:8091/json/ingest)
    guard_header=$(awk 'BEGIN{IGNORECASE=1} /^X-Json-Guard-Inspection-Us:/ {gsub("\r", "", $2); print $2}' "$work/headers")
    if [ "$status" != 400 ] || [ -z "$guard_header" ]; then
        printf 'native Guard ordering/malformed check failed\n' >&2
        return 2
    fi
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        --data-binary '{"value":"1\u0027 OR \u00271\u0027=\u00271\u0027 UNION SELECT password FROM users--"}' \
        http://127.0.0.1:8091/json/ingest)
    if [ "$status" != 403 ]; then
        printf 'native Guard plus CRS attack check failed: HTTP %s\n' "$status" >&2
        return 2
    fi

    start_target coraza-crs
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' --data-binary @"$work/valid.json" \
        http://127.0.0.1:8092/json/ingest)
    if [ "$status" != 200 ]; then
        printf 'native Coraza valid-body check failed: HTTP %s\n' "$status" >&2
        return 2
    fi
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        --data-binary '{"value":"1\u0027 OR \u00271\u0027=\u00271\u0027 UNION SELECT password FROM users--"}' \
        http://127.0.0.1:8092/json/ingest)
    if [ "$status" != 403 ]; then
        printf 'native Coraza CRS attack check failed: HTTP %s\n' "$status" >&2
        return 2
    fi
    stop_targets
    rm -rf "$work"
}

start_monitors() {
    local out=$1
    MONITOR_PIDS=()
    LC_ALL=C vmstat 1 >"$out/vmstat.log" 2>&1 & MONITOR_PIDS+=("$!")
    LC_ALL=C mpstat -P ALL 1 >"$out/mpstat.log" 2>&1 & MONITOR_PIDS+=("$!")
    LC_ALL=C iostat -xz 1 >"$out/iostat.log" 2>&1 & MONITOR_PIDS+=("$!")
    LC_ALL=C pidstat -durh 1 >"$out/pidstat.log" 2>&1 & MONITOR_PIDS+=("$!")
}

stop_monitors() {
    local pid
    for pid in "${MONITOR_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${MONITOR_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    MONITOR_PIDS=()
}

run_suite() {
    local engine=$1 suite=$2 workers=$3 mode=$4 regex=${5:-}
    local out="$RUN_DIR/profiles/$engine/${suite}-w${workers}"
    local extra=()
    mkdir -p "$out"
    case "$mode" in
        smoke)
            extra+=(--max-repeat 1 --quick)
            if [ "$suite" = correctness ]; then
                extra+=(--case-regex '^(valid_|malformed_|invalid_|unpaired_|trailing_|duplicate_|depth_10[01]|wide_array_10001|key_length_4097|number_length_257|tokens_100001|attack_sqli_small|fp_apostrophe)')
            fi
            ;;
        quick) extra+=(--max-repeat 2 --quick) ;;
        full) extra+=(--warmup) ;;
        large) extra+=(--max-repeat 1 --case-regex "$regex") ;;
    esac

    python3 "$ROOT/scripts/native_host_metrics.py" snapshot --output "$out/host-before.json"
    start_monitors "$out"
    set +e
    python3 "$ROOT/scripts/cross_waf_bench.py" --engines "$ENGINE_FILE" run \
        --engine "$engine" --suite "$suite" --payload-dir "$PAYLOAD_DIR" \
        --output-dir "$out" --workers "$workers" --timeout "$TIMEOUT" \
        "${extra[@]}" 2>&1 | tee "$out/run.log"
    local status=${PIPESTATUS[0]}
    set -e
    stop_monitors
    python3 "$ROOT/scripts/native_host_metrics.py" snapshot --output "$out/host-after.json"
    if [ -f "$out/results.json" ]; then
        python3 "$ROOT/scripts/native_host_metrics.py" annotate \
            --results "$out/results.json" --before "$out/host-before.json" \
            --after "$out/host-after.json"
    fi
    if [ "$status" -eq 1 ]; then
        FINDINGS=1
        return 0
    fi
    return "$status"
}

capture_environment() {
    python3 "$ROOT/scripts/native_host_metrics.py" environment \
        --output-dir "$RUN_DIR" --server-label "$SERVER_LABEL" --repo "$ROOT"
    cp "$PREFIX/BUILD_MANIFEST.txt" "$RUN_DIR/configs/BUILD_MANIFEST.txt"
    cp "$ENGINE_FILE" "$RUN_DIR/configs/engines.json"
    cp "$ETC/lab.env" "$RUN_DIR/configs/lab.env"
    cp "$VERSIONS_FILE" "$RUN_DIR/configs/versions.env"
    cp -a "$ROOT/benchmark/native/nginx.conf" "$ROOT/benchmark/native/Caddyfile" \
        "$RUN_DIR/configs/"
    cp -a "$ROOT/benchmark/native/systemd" "$RUN_DIR/configs/"
    cp -a "$ETC" "$RUN_DIR/configs/installed"
    cp -a "$ROOT/benchmark/nginx" "$ROOT/benchmark/modsecurity" \
        "$ROOT/benchmark/coraza" "$RUN_DIR/configs/"
    lscpu --json >"$RUN_DIR/logs/lscpu.json"
    free -b >"$RUN_DIR/logs/free.txt"
    lsblk --json --bytes >"$RUN_DIR/logs/lsblk.json"
    df -B1 >"$RUN_DIR/logs/df.txt"
    swapon --show --bytes >"$RUN_DIR/logs/swapon.txt"
    uname -a >"$RUN_DIR/logs/uname.txt"
    timedatectl >"$RUN_DIR/logs/timedatectl.txt" 2>&1 || true
    sysctl kernel.version vm.swappiness vm.overcommit_memory \
        fs.file-max net.core.somaxconn >"$RUN_DIR/logs/sysctl.txt" 2>&1 || true
    dpkg-query -W -f='${Package}\t${Version}\n' >"$RUN_DIR/logs/packages.tsv"
    git -C "$ROOT" status --short >"$RUN_DIR/logs/git-status.txt" 2>&1 || true
    git -C "$ROOT" diff --stat >"$RUN_DIR/logs/git-diff-stat.txt" 2>&1 || true
    "$PREFIX/nginx/sbin/nginx" -V >"$RUN_DIR/logs/nginx-version.txt" 2>&1
    LD_LIBRARY_PATH="$PREFIX/modsecurity/lib:$PREFIX/modsecurity/lib64" \
        ldd "$PREFIX/nginx/sbin/nginx" >"$RUN_DIR/logs/nginx-ldd.txt"
    LD_LIBRARY_PATH="$PREFIX/modsecurity/lib:$PREFIX/modsecurity/lib64" \
        ldd "$PREFIX/nginx/modules/ngx_http_json_guard_module.so" \
        >"$RUN_DIR/logs/json-guard-module-ldd.txt"
    LD_LIBRARY_PATH="$PREFIX/modsecurity/lib:$PREFIX/modsecurity/lib64" \
        ldd "$PREFIX/nginx/modules/ngx_http_modsecurity_module.so" \
        >"$RUN_DIR/logs/modsecurity-module-ldd.txt"
    "$PREFIX/bin/caddy" build-info >"$RUN_DIR/logs/caddy-build-info.txt"
    cc --version >"$RUN_DIR/logs/cc-version.txt"
    "$TOOLCHAIN/go/bin/go" version >"$RUN_DIR/logs/go-version.txt"
}

run_matrix() {
    local mode=$1 engine crs
    ensure_setup
    new_run_dir
    python3 "$ROOT/scripts/cross_waf_bench.py" generate --payload-dir "$PAYLOAD_DIR"
    capture_environment

    if [ "$mode" = large ]; then
        local large_engines="nginx-baseline nginx-guard nginx-modsecurity-processor nginx-guard-modsecurity-processor coraza-processor"
        for engine in $large_engines; do
            start_target "$engine"
            run_suite "$engine" processor 1 large '^(blob_50m|blob_100m|blob_chunked_100m)$'
            start_target "$engine"
            run_suite "$engine" correctness 1 large '^(string_length_[0-9]+|blob_129m)$'
        done
    else
        for engine in $ENGINES; do
            start_target "$engine"
            run_suite "$engine" correctness 1 "$mode"
            if [ "$mode" != smoke ]; then
                crs=$(engine_field "$engine" crs)
                if [ "$crs" = True ]; then
                    start_target "$engine"
                    run_suite "$engine" crs 1 "$mode"
                    start_target "$engine"
                    run_suite "$engine" mixed 4 "$mode"
                else
                    start_target "$engine"
                    run_suite "$engine" processor 1 "$mode"
                    if [ "$mode" = full ]; then
                        start_target "$engine"
                        run_suite "$engine" processor 2 "$mode"
                        start_target "$engine"
                        run_suite "$engine" processor 4 "$mode"
                    fi
                fi
            fi
        done
    fi
    stop_targets
    python3 "$ROOT/scripts/cross_waf_bench.py" report --results-root "$RUN_DIR"
    cp "$PAYLOAD_DIR/manifest.json" "$RUN_DIR/configs/payload-manifest.json"
    find "$RUN_DIR/configs" -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >"$RUN_DIR/configs/SHA256SUMS"
    owner=${SUDO_USER:-root}
    chown -R "$owner":"$(id -gn "$owner")" "$RUN_DIR" 2>/dev/null || true
    if [ "$FINDINGS" -ne 0 ]; then
        return 3
    fi
}

resolve_run_dir() {
    if [ -z "$RUN_DIR" ]; then
        if [ ! -r "$LAST_RUN_FILE" ]; then
            printf 'no prior native run found; set RUN_DIR explicitly\n' >&2
            return 2
        fi
        RUN_DIR=$(cat "$LAST_RUN_FILE")
    fi
    if [ ! -d "$RUN_DIR" ]; then
        printf 'run directory does not exist: %s\n' "$RUN_DIR" >&2
        return 2
    fi
}

bundle() {
    resolve_run_dir
    local name temporary archive owner
    name=$(basename "$RUN_DIR")
    archive="$RUN_DIR/bundle.tar.zst"
    temporary=$(mktemp "$(dirname "$RUN_DIR")/.$name.XXXXXX.tar.zst")
    rm -f "$archive" "$archive.sha256"
    tar --zstd -cf "$temporary" -C "$(dirname "$RUN_DIR")" "$name"
    mv "$temporary" "$archive"
    (cd "$RUN_DIR" && sha256sum bundle.tar.zst >bundle.tar.zst.sha256)
    owner=${SUDO_USER:-root}
    chown -R "$owner":"$(id -gn "$owner")" "$RUN_DIR" 2>/dev/null || true
    printf 'bundle: %s\nchecksum: %s\n' "$archive" "$archive.sha256"
}

main() {
    local command_name=${1:-}
    case "$command_name" in
        setup) setup ;;
        smoke|quick|full|large)
            set +e
            (set -e; run_matrix "$command_name")
            status=$?
            set -e
            exit "$status"
            ;;
        bundle)
            require_root
            bundle
            ;;
        all)
            require_root
            new_run_dir
            findings_status=0
            set +e
            setup 2>&1 | tee "$RUN_DIR/logs/setup.log"
            status=${PIPESTATUS[0]}
            if [ "$status" -eq 0 ]; then
                (set -e; run_matrix full)
                run_status=$?
                if [ "$run_status" -eq 3 ]; then
                    findings_status=3
                elif [ "$run_status" -ne 0 ]; then
                    status=$run_status
                fi
            fi
            if [ "$status" -eq 0 ]; then
                (set -e; run_matrix large)
                run_status=$?
                if [ "$run_status" -eq 3 ]; then
                    findings_status=3
                elif [ "$run_status" -ne 0 ]; then
                    status=$run_status
                fi
            fi
            if [ "$status" -eq 0 ] && [ "$findings_status" -ne 0 ]; then
                status=$findings_status
            fi
            bundle_status=0
            bundle || bundle_status=$?
            set -e
            if [ "$status" -ne 0 ]; then exit "$status"; fi
            exit "$bundle_status"
            ;;
        -h|--help|help) usage ;;
        *) usage >&2; exit 2 ;;
    esac
}

trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
validate_inputs
main "$@"
