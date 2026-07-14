#!/usr/bin/env bash
# Integration tests against a running ngx_json_guard + ModSecurity container.
#
# Usage:
#   ./integration/run_integration_tests.sh [base_url]
#
# Default base_url: http://127.0.0.1:8080
#
# Proves:
#   1. Valid JSON is accepted by json_guard and reaches upstream.
#   2. Malformed JSON is rejected with 400 by json_guard (ordering).
#   3. Structurally valid JSON with attack marker is blocked by ModSecurity (403).
#   4. Large valid JSON with tail marker is fully preserved (upstream + ModSec).
#   5. Non-JSON Content-Type skips json_guard structural validation.

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080}"
PASS=0
FAIL=0
WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/jg_integration_$$"
mkdir -p "$TMPDIR"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }

check() {
  local name="$1"
  shift
  if "$@"; then
    green "PASS  $name"
    PASS=$((PASS + 1))
  else
    red "FAIL  $name"
    FAIL=$((FAIL + 1))
  fi
}

http_code() {
  # args: method url content_type body_file
  local method="$1" url="$2" ctype="$3" body="$4"
  curl -sS -o "$TMPDIR/body.out" -w "%{http_code}" \
    -X "$method" "$url" \
    -H "Content-Type: $ctype" \
    --data-binary @"$body"
}

wait_ready() {
  local i
  for i in $(seq 1 60); do
    if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "service not ready at $BASE" >&2
  return 1
}

keepalive_two_posts() {
  python3 - "$BASE" <<'PY'
import http.client
import json
import sys
from urllib.parse import urlparse

base = urlparse(sys.argv[1])
conn = http.client.HTTPConnection(base.hostname, base.port, timeout=5)
sock_fd = None

for request_id in (1, 2):
    body = json.dumps({"keepalive_request": request_id}, separators=(",", ":"))
    conn.request(
        "POST",
        "/api/echo",
        body=body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
    )
    response = conn.getresponse()
    response.read()
    if response.status != 200:
        raise SystemExit(f"request {request_id} returned {response.status}")
    if conn.sock is None:
        raise SystemExit(f"request {request_id} closed the client connection")
    if sock_fd is None:
        sock_fd = conn.sock.fileno()
    elif conn.sock.fileno() != sock_fd:
        raise SystemExit("second request used a different connection")

conn.close()
PY
}

echo "ngx_json_guard integration tests"
echo "base: $BASE"
echo "================================"

wait_ready
info "service ready"

# --- 1. Valid small JSON ---
printf '%s' '{"hello":"world","n":1}' >"$TMPDIR/valid.json"
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/valid.json")
check "1. valid small JSON -> 200" test "$CODE" = "200"
if [[ "$CODE" == "200" ]]; then
  grep -q '"ok":true' "$TMPDIR/body.out" \
    && check "1b. upstream received body" true \
    || check "1b. upstream received body" false
fi

# --- 2. Malformed trailing comma -> 400 from json_guard ---
printf '%s' '{"a":1,}' >"$TMPDIR/bad.json"
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/bad.json")
check "2. malformed trailing comma -> 400" test "$CODE" = "400"

# --- 3. Valid JSON with attack marker -> 403 ModSecurity ---
printf '%s' '{"q":"JG_ATTACK_MARKER_sqli select"}' >"$TMPDIR/attack.json"
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/attack.json")
check "3. attack marker blocked by ModSecurity -> 403" test "$CODE" = "403"

# --- 4. Large valid JSON with tail marker (body preservation) ---
python3 - <<'PY' >"$TMPDIR/large.json"
import json
items = [{"i": i, "pad": "x" * 64} for i in range(5000)]
doc = {"items": items, "tail": "JG_TAIL_MARKER_7f3a9c"}
print(json.dumps(doc, separators=(",", ":")))
PY
BYTES=$(wc -c <"$TMPDIR/large.json" | tr -d ' ')
info "large payload bytes=$BYTES"
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/large.json")
check "4. large valid JSON with tail marker -> 200" test "$CODE" = "200"
if [[ "$CODE" == "200" ]]; then
  if python3 - <<PY
import json, sys
resp = json.load(open("$TMPDIR/body.out"))
rec = resp.get("received") or resp
ok = (
    rec.get("has_tail_marker") is True
    and int(rec.get("body_len") or 0) == $BYTES
)
if not ok:
    print("received:", rec, file=sys.stderr)
sys.exit(0 if ok else 1)
PY
  then
    check "4b. upstream saw full body + tail marker" true
  else
    check "4b. upstream saw full body + tail marker" false
  fi
fi

# --- 5. Non-JSON content-type skips structural validation of JSON-looking body ---
# Malformed JSON bytes with text/plain should NOT get 400 from json_guard.
printf '%s' '{"a":1,}' >"$TMPDIR/plain.json"
CODE=$(http_code POST "$BASE/api/echo" "text/plain" "$TMPDIR/plain.json")
# May be 200 (upstream) — not 400 from json_guard
check "5. text/plain malformed JSON not 400 from guard" test "$CODE" != "400"

# --- 6. application/vnd.api+json accepted as JSON ---
printf '%s' '{"data":{"type":"t","id":"1"}}' >"$TMPDIR/vnd.json"
CODE=$(http_code POST "$BASE/api/echo" "application/vnd.api+json" "$TMPDIR/vnd.json")
check "6. application/vnd.api+json valid -> 200" test "$CODE" = "200"

# --- 7. Depth limit -> 413 ---
python3 - <<'PY' >"$TMPDIR/deep.json"
s = '{"a":' * 40 + '1' + '}' * 40
print(s)
PY
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/deep.json")
check "7. excessive nesting -> 413" test "$CODE" = "413"

# --- 8. Ordering contrast: malformed on /noguard/ is NOT rejected by json_guard ---
# Without guard, malformed JSON reaches upstream (200) unless ModSecurity cares
# about JSON validity (our rules do not).
printf '%s' '{"a":1,}' >"$TMPDIR/bad2.json"
CODE=$(http_code POST "$BASE/noguard/echo" "application/json" "$TMPDIR/bad2.json")
check "8. /noguard/ malformed not blocked by json_guard (expect 200)" test "$CODE" = "200"

# --- 9. Duplicate keys rejected when enabled in docker/nginx.conf ---
printf '%s' '{"a":1,"a":2}' >"$TMPDIR/dup.json"
CODE=$(http_code POST "$BASE/api/echo" "application/json" "$TMPDIR/dup.json")
check "9. duplicate object key -> 400" test "$CODE" = "400"

# --- 10. JSON bodies are guarded regardless of HTTP method ---
printf '%s' '{"a":1,}' >"$TMPDIR/delete-bad.json"
CODE=$(http_code DELETE "$BASE/api/echo" "application/json" "$TMPDIR/delete-bad.json")
check "10. malformed DELETE JSON -> 400" test "$CODE" = "400"

# --- 11. Body-read request reference is released for keep-alive reuse ---
check "11. two JSON requests reuse one keep-alive connection" keepalive_two_posts

# --- 12. Content-Type matching is case-insensitive and trims media-type OWS ---
printf '%s' '{"case":"mixed-content-type"}' >"$TMPDIR/mixed-ctype.json"
CODE=$(http_code POST "$BASE/api/echo" \
  " Application/Vnd.Api+Json ; charset=utf-8" "$TMPDIR/mixed-ctype.json")
check "12. mixed-case +json Content-Type with OWS -> 200" test "$CODE" = "200"

echo "================================"
echo "Passed: $PASS  Failed: $FAIL"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
exit 0
