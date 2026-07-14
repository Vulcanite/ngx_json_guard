#!/usr/bin/env python3
"""Focused tests for native benchmark support code."""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import sys
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


metrics = load_module("native_host_metrics", ROOT / "scripts/native_host_metrics.py")
sink = load_module("native_body_sink", ROOT / "benchmark/native_body_sink.py")


class NativeBenchmarkTests(unittest.TestCase):
    def test_streaming_sink_hash_and_timing_header(self) -> None:
        server = sink.SinkServer(("127.0.0.1", 0), sink.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = b'{"payload":"' + b"x" * (2 * 1024 * 1024) + b'"}'
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=10
            )
            connection.request(
                "POST", "/json/ingest", body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("X-Upstream-App"), "native-body-sink")
            self.assertIsNotNone(response.getheader("X-Upstream-Processing-Us"))
            self.assertEqual(payload["body_len"], len(body))
            self.assertEqual(payload["sha256"], hashlib.sha256(body).hexdigest())
            connection.close()

            metrics_connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=10
            )
            metrics_connection.request("GET", "/metrics")
            metrics_response = metrics_connection.getresponse()
            metric_values = json.loads(metrics_response.read())
            self.assertEqual(metric_values["requests"], 1)
            self.assertEqual(metric_values["body_bytes"], len(body))
            self.assertEqual(metric_values["errors"], 0)
            if Path("/sys/fs/cgroup/cgroup.controllers").exists():
                self.assertIn("cgroup_cpu_usage_usec", metric_values)
                self.assertIn("cgroup_memory_current_bytes", metric_values)
            metrics_connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_cpu_steal_calculation(self) -> None:
        before = {"cpu": {"user": 100, "system": 50, "idle": 850, "steal": 0}}
        after = {"cpu": {"user": 180, "system": 70, "idle": 890, "steal": 10}}
        result = metrics.cpu_deltas(before, after)
        self.assertAlmostEqual(result["steal_percent"], 10 / 150 * 100)
        self.assertAlmostEqual(result["busy_percent"], 110 / 150 * 100)

    def test_native_engine_matrix(self) -> None:
        engines = json.loads(
            (ROOT / "benchmark/native/engines.json").read_text()
        )
        self.assertEqual(len(engines), 8)
        self.assertEqual(sum(item["json_guard"] for item in engines.values()), 3)
        self.assertEqual(sum(item["crs"] for item in engines.values()), 3)
        for engine in engines.values():
            self.assertEqual(engine["runtime"]["type"], "systemd")
            self.assertEqual(engine["backend_units"], ["ngx-json-guard-backend.service"])
            self.assertEqual(
                engine["backend_metrics_url"], "http://127.0.0.1:9100/metrics"
            )
            self.assertTrue(engine["base_url"].startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
