#!/usr/bin/env python3
"""Bounded-memory HTTP body sink for native WAF benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


CHUNK = 1024 * 1024


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def cgroup_snapshot() -> dict[str, int]:
    """Return flat cgroup-v2 counters that the remote harness can diff."""
    try:
        entry = next(
            line for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")
        )
    except (OSError, StopIteration):
        return {}

    cgroup = Path("/sys/fs/cgroup") / entry[3:].lstrip("/")
    result: dict[str, int] = {}

    for filename, prefix in (
        ("cpu.stat", "cgroup_cpu_"),
        ("memory.events", "cgroup_memory_event_"),
    ):
        try:
            lines = (cgroup / filename).read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) == 2:
                try:
                    result[prefix + fields[0]] = int(fields[1])
                except ValueError:
                    continue

    for filename, key in (
        ("memory.current", "cgroup_memory_current_bytes"),
        ("memory.peak", "cgroup_memory_peak_bytes"),
    ):
        value = _read_int(cgroup / filename)
        if value is not None:
            result[key] = value

    io_totals: dict[str, int] = {}
    try:
        for line in (cgroup / "io.stat").read_text().splitlines():
            for field in line.split()[1:]:
                name, separator, raw_value = field.partition("=")
                if not separator:
                    continue
                try:
                    io_totals[name] = io_totals.get(name, 0) + int(raw_value)
                except ValueError:
                    continue
    except OSError:
        pass
    result.update({f"cgroup_io_{key}": value for key, value in io_totals.items()})

    for resource in ("cpu", "memory", "io"):
        try:
            lines = (cgroup / f"{resource}.pressure").read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if not fields:
                continue
            for field in fields[1:]:
                if field.startswith("total="):
                    try:
                        result[
                            f"cgroup_{resource}_pressure_{fields[0]}_total_usec"
                        ] = int(field.removeprefix("total="))
                    except ValueError:
                        pass
    return result


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started_ns = time.monotonic_ns()
        self.requests = 0
        self.errors = 0
        self.body_bytes = 0
        self.processing_us = 0
        self.max_processing_us = 0
        self.active = 0
        self.max_active = 0

    def begin(self) -> None:
        with self.lock:
            self.requests += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)

    def finish(self, body_bytes: int, processing_us: int, error: bool = False) -> None:
        with self.lock:
            self.active = max(0, self.active - 1)
            self.errors += int(error)
            self.body_bytes += body_bytes
            self.processing_us += processing_us
            self.max_processing_us = max(self.max_processing_us, processing_us)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            metrics = {
                "uptime_us": (time.monotonic_ns() - self.started_ns) // 1000,
                "requests": self.requests,
                "errors": self.errors,
                "body_bytes": self.body_bytes,
                "processing_us": self.processing_us,
                "max_processing_us": self.max_processing_us,
                "active": self.active,
                "max_active": self.max_active,
            }
        metrics.update(cgroup_snapshot())
        return metrics


METRICS = Metrics()


class SinkServer(ThreadingHTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ngx-json-guard-benchmark-sink/1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[native-body-sink] " + (fmt % args) + "\n")

    def read_and_hash(self) -> tuple[int, str, int]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        remaining = int(raw_length)
        if remaining < 0:
            raise ValueError("negative Content-Length")
        digest = hashlib.sha256()
        received = 0
        started = time.perf_counter_ns()
        while remaining:
            chunk = self.rfile.read(min(CHUNK, remaining))
            if not chunk:
                raise ConnectionError("request body ended early")
            digest.update(chunk)
            received += len(chunk)
            remaining -= len(chunk)
        elapsed_us = (time.perf_counter_ns() - started) // 1000
        return received, digest.hexdigest(), elapsed_us

    def send_json(self, status: int, payload: dict[str, object], elapsed_us: int) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-App", "native-body-sink")
        self.send_header("X-Upstream-Processing-Us", str(elapsed_us))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def handle_body(self) -> None:
        METRICS.begin()
        try:
            body_len, digest, elapsed_us = self.read_and_hash()
        except (ValueError, ConnectionError) as exc:
            METRICS.finish(0, 0, error=True)
            self.send_json(400, {"ok": False, "error": str(exc)}, 0)
            return
        METRICS.finish(body_len, elapsed_us)
        self.send_json(
            200,
            {
                "ok": True,
                "body_len": body_len,
                "sha256": digest,
                "processing_us": elapsed_us,
            },
            elapsed_us,
        )

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/health"):
            self.send_json(200, {"ok": True, "app": "native-body-sink"}, 0)
            return
        if self.path.startswith("/metrics"):
            self.send_json(200, {"ok": True, **METRICS.snapshot()}, 0)
            return
        self.send_json(200, {"ok": True, "body_len": 0}, 0)

    def do_POST(self) -> None:  # noqa: N802
        self.handle_body()

    def do_PUT(self) -> None:  # noqa: N802
        self.handle_body()

    def do_PATCH(self) -> None:  # noqa: N802
        self.handle_body()

    def do_DELETE(self) -> None:  # noqa: N802
        self.handle_body()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    args = parser.parse_args()
    server = SinkServer((args.host, args.port), Handler)
    print(f"native body sink listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
