#!/bin/sh
set -eu

mkdir -p /tmp/client_body_temp /tmp/proxy_temp /var/log/nginx /var/log/modsec

START_INTERNAL_BACKEND="${START_INTERNAL_BACKEND:-1}"
BACKEND_HEALTH_URL="${BACKEND_HEALTH_URL:-http://127.0.0.1:9000/health}"
ECHO_PID=""

cleanup() {
  if [ -n "$ECHO_PID" ]; then
    kill "$ECHO_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Start echo backend for the integration image unless an external upstream is
# configured by compose.
if [ "$START_INTERNAL_BACKEND" != "0" ]; then
  python3 /usr/local/bin/echo_backend.py >/var/log/nginx/echo_backend.log 2>&1 &
  ECHO_PID=$!
fi

# Wait for backend.
i=0
while [ "$i" -lt 50 ]; do
  if curl -fsS "$BACKEND_HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.1
done

nginx -t
exec nginx -g 'daemon off;'
