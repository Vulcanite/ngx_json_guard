#!/usr/bin/env bash
# Build the Docker image and run integration tests.
#
# From repo root:
#   ./scripts/run_docker_integration.sh
#
# Options via env:
#   IMAGE=ngx_json_guard:test
#   PORT=8080
#   SKIP_BUILD=1   # use existing image

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-ngx_json_guard:test}"
PORT="${PORT:-8080}"
NAME="ngx_json_guard_itest_$$"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> Building $IMAGE (this compiles NGINX + ModSecurity; may take several minutes)"
  docker build -f docker/Dockerfile -t "$IMAGE" .
fi

echo "==> Starting container on port $PORT"
docker run -d --name "$NAME" -p "${PORT}:8080" "$IMAGE" >/dev/null

echo "==> Waiting for health"
for i in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  # surface early crash logs
  if ! docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true; then
    echo "container exited early:" >&2
    docker logs "$NAME" 2>&1 | tail -80 >&2 || true
    exit 1
  fi
  sleep 1
done

if ! curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
  echo "health check failed; logs:" >&2
  docker logs "$NAME" 2>&1 | tail -100 >&2 || true
  exit 1
fi

echo "==> Running integration tests"
./integration/run_integration_tests.sh "http://127.0.0.1:${PORT}"
RC=$?

echo "==> Sample container logs (json_guard / modsec)"
docker logs "$NAME" 2>&1 | grep -E 'json_guard:|ModSecurity|modsecurity' | tail -40 || true

exit "$RC"
