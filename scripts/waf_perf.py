#!/usr/bin/env python3
"""Mixed correctness and performance workload for the constrained WAF lab."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import http.client
import json
import math
import os
import random
import statistics
import subprocess
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


MIB = 1024 * 1024
SQLI = "1' OR '1'='1' UNION SELECT password FROM users--"
XSS = "<script>alert(document.domain)</script>"
CMDI = "; cat /etc/passwd; id"


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    group: str
    method: str
    path: str
    content_type: str | None
    body: bytes
    expected: tuple[int, ...]
    large: bool = False
    malicious: bool = False


@dataclasses.dataclass
class Result:
    case: Case
    status: int | None
    elapsed_ms: float
    guard_us: int | None
    response_bytes: int
    error: str | None

    @property
    def correct(self) -> bool:
        return self.error is None and self.status in self.case.expected


def exact_blob_json(size: int, tail: str = "clean") -> bytes:
    doc = {"kind": "blob", "padding": "", "tail": tail}
    base = json.dumps(doc, separators=(",", ":")).encode()
    padding = max(0, size - len(base))
    doc["padding"] = "x" * padding
    body = json.dumps(doc, separators=(",", ":")).encode()
    if len(body) != size:
        raise RuntimeError(f"blob generator produced {len(body)} bytes, wanted {size}")
    return body


def exact_records_json(size: int, tail: str = "clean") -> bytes:
    prefix = bytearray(b'{"records":[')
    record = b'{"id":123,"name":"normal","active":true,"value":"abcdefghijklmnopqrstuvwxyz"},'
    reserve = len(b'],"padding":"","tail":""}') + len(tail.encode())
    while len(prefix) + len(record) + reserve < size:
        prefix.extend(record)
    if prefix[-1:] == b",":
        prefix.pop()
    suffix_fixed = b'],"padding":"' + b'","tail":' + json.dumps(tail).encode() + b"}"
    padding_len = size - len(prefix) - len(suffix_fixed)
    if padding_len < 0:
        raise RuntimeError("target too small for records payload")
    prefix.extend(b'],"padding":"')
    prefix.extend(b"p" * padding_len)
    prefix.extend(b'","tail":')
    prefix.extend(json.dumps(tail).encode())
    prefix.extend(b"}")
    body = bytes(prefix)
    if len(body) != size:
        raise RuntimeError(f"records generator produced {len(body)} bytes, wanted {size}")
    return body


def build_cases(payload_dir: Path, large_mib: int) -> list[Case]:
    payload_dir.mkdir(parents=True, exist_ok=True)
    large_size = large_mib * MIB
    one_mib = exact_blob_json(MIB)
    large_blob = exact_blob_json(large_size)
    large_records = exact_records_json(large_size)
    large_attack = exact_blob_json(large_size, SQLI)
    malformed = large_blob[:-1] + b",}"

    fixtures = {
        "normal-1m.json": one_mib,
        f"normal-blob-{large_mib}m.json": large_blob,
        f"normal-records-{large_mib}m.json": large_records,
        f"tail-sqli-{large_mib}m.json": large_attack,
        f"malformed-tail-{large_mib}m.json": malformed,
    }
    for name, body in fixtures.items():
        path = payload_dir / name
        if not path.exists() or path.stat().st_size != len(body):
            path.write_bytes(body)

    def post_json(name: str, body: bytes, expected: tuple[int, ...], **kw: Any) -> Case:
        return Case(name, "json", "POST", "/json/ingest", "application/json", body, expected, **kw)

    normal_json = json.dumps(
        {"request_id": 42, "user": {"name": "Ada", "roles": ["reader", "writer"]}, "ok": True},
        separators=(",", ":"),
    ).encode()

    return [
        Case("web_get", "web", "GET", "/web/?title=Dashboard", None, b"", (200,)),
        Case("web_query_normal", "web", "GET", "/web/search?q=quarterly+report", None, b"", (200,)),
        Case(
            "web_query_sqli", "web", "GET",
            "/web/search?q=" + urllib.parse.quote(SQLI), None, b"", (403,), malicious=True,
        ),
        Case(
            "web_query_xss", "web", "GET",
            "/web/search?q=" + urllib.parse.quote(XSS), None, b"", (403,), malicious=True,
        ),
        post_json("json_small_object", normal_json, (200,)),
        post_json("json_small_array", b'[{"id":1},{"id":2},{"id":3}]', (200,)),
        post_json("json_sqli", json.dumps({"query": SQLI}).encode(), (403,), malicious=True),
        post_json("json_xss", json.dumps({"comment": XSS}).encode(), (403,), malicious=True),
        post_json("json_command_injection", json.dumps({"command": CMDI}).encode(), (403,), malicious=True),
        post_json("json_1m_clean", one_mib, (200,), large=True),
        post_json(f"json_{large_mib}m_blob_clean", large_blob, (200,), large=True),
        # This body is valid JSON but intentionally exceeds the constrained
        # profile's cardinality limits. It must fail before CRS's per-argument
        # rules turn a high-member document into unbounded CPU work.
        post_json(f"json_{large_mib}m_records_limit", large_records, (413,), large=True),
        post_json(
            f"json_{large_mib}m_tail_sqli", large_attack, (403,),
            large=True, malicious=True,
        ),
        post_json(f"json_{large_mib}m_malformed_tail", malformed, (400,), large=True),
        Case(
            "xml_normal", "xml", "POST", "/xml/ingest", "application/xml",
            b'<?xml version="1.0"?><order><id>42</id><item>book</item></order>', (200,),
        ),
        Case(
            "xml_sqli", "xml", "POST", "/xml/ingest", "application/xml",
            f"<request><query>{SQLI}</query></request>".encode(), (403,), malicious=True,
        ),
        Case(
            "xml_xxe", "xml", "POST", "/xml/ingest", "application/xml",
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            (400, 403), malicious=True,
        ),
        Case(
            "form_normal", "form", "POST", "/form/submit",
            "application/x-www-form-urlencoded", b"name=Ada&department=engineering", (200,),
        ),
        Case(
            "form_sqli", "form", "POST", "/form/submit",
            "application/x-www-form-urlencoded",
            urllib.parse.urlencode({"username": "admin", "query": SQLI}).encode(),
            (403,), malicious=True,
        ),
        Case(
            "form_command_injection", "form", "POST", "/form/submit",
            "application/x-www-form-urlencoded",
            urllib.parse.urlencode({"host": CMDI}).encode(), (403,), malicious=True,
        ),
        Case(
            "text_plain_normal", "web", "POST", "/web/events", "text/plain",
            b"ordinary application event", (200,),
        ),
    ]


def request_once(base: urllib.parse.SplitResult, case: Case, timeout: float) -> Result:
    headers = {"Connection": "close", "Host": "waf.local"}
    if case.content_type:
        headers["Content-Type"] = case.content_type
    if case.body:
        headers["Content-Length"] = str(len(case.body))

    started = time.perf_counter()
    try:
        conn = http.client.HTTPConnection(base.hostname, base.port, timeout=timeout)
        conn.request(case.method, case.path, body=case.body or None, headers=headers)
        response = conn.getresponse()
        data = response.read()
        elapsed_ms = (time.perf_counter() - started) * 1000
        raw_guard = response.getheader("X-Json-Guard-Inspection-Us")
        guard_us = int(raw_guard) if raw_guard and raw_guard.isdigit() else None
        status = response.status
        conn.close()
        return Result(case, status, elapsed_ms, guard_us, len(data), None)
    except Exception as exc:  # noqa: BLE001
        return Result(case, None, (time.perf_counter() - started) * 1000, None, 0, str(exc))


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"avg": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "avg": statistics.fmean(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
    }


def docker_exec(container: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["docker", "exec", container, "cat", path], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def parse_kv(text: str | None) -> dict[str, int]:
    result: dict[str, int] = {}
    if text:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                result[parts[0]] = int(parts[1])
    return result


def cgroup_snapshot(container: str) -> dict[str, Any]:
    return {
        "cpu": parse_kv(docker_exec(container, "/sys/fs/cgroup/cpu.stat")),
        "memory_events": parse_kv(docker_exec(container, "/sys/fs/cgroup/memory.events")),
        "memory_current": int(docker_exec(container, "/sys/fs/cgroup/memory.current") or 0),
        "memory_peak": int(docker_exec(container, "/sys/fs/cgroup/memory.peak") or 0),
    }


def summarize(results: list[Result], wall_s: float, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    by_case: dict[str, list[Result]] = defaultdict(list)
    by_group: dict[str, list[Result]] = defaultdict(list)
    for result in results:
        by_case[result.case.name].append(result)
        by_group[result.case.group].append(result)

    def summarize_set(items: list[Result]) -> dict[str, Any]:
        elapsed = [r.elapsed_ms for r in items if r.error is None]
        guard = [float(r.guard_us) / 1000 for r in items if r.guard_us is not None]
        return {
            "count": len(items),
            "correct": sum(r.correct for r in items),
            "statuses": dict(Counter(str(r.status) if r.status is not None else "ERR" for r in items)),
            "latency_ms": stats(elapsed),
            "guard_ms": stats(guard),
        }

    cpu_before = before.get("cpu", {})
    cpu_after = after.get("cpu", {})
    cpu_usage = max(0, cpu_after.get("usage_usec", 0) - cpu_before.get("usage_usec", 0))
    throttled = max(0, cpu_after.get("throttled_usec", 0) - cpu_before.get("throttled_usec", 0))
    body_bytes = sum(len(r.case.body) for r in results)

    return {
        "wall_seconds": wall_s,
        "requests": len(results),
        "correct": sum(r.correct for r in results),
        "body_bytes": body_bytes,
        "requests_per_second": len(results) / wall_s if wall_s else 0,
        "body_mib_per_second": body_bytes / MIB / wall_s if wall_s else 0,
        "overall": summarize_set(results),
        "by_group": {name: summarize_set(items) for name, items in sorted(by_group.items())},
        "by_case": {name: summarize_set(items) for name, items in sorted(by_case.items())},
        "cgroup": {
            "cpu_usage_seconds": cpu_usage / 1_000_000,
            "average_cpu_percent": cpu_usage / (wall_s * 1_000_000) * 100 if wall_s else 0,
            "throttled_seconds": throttled / 1_000_000,
            "nr_throttled_delta": max(
                0, cpu_after.get("nr_throttled", 0) - cpu_before.get("nr_throttled", 0)
            ),
            "memory_peak_bytes": after.get("memory_peak", 0),
            "memory_events": after.get("memory_events", {}),
        },
    }


def fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def markdown_report(meta: dict[str, Any], summary: dict[str, Any], results: list[Result]) -> str:
    lines = [
        "# WAF Performance Report",
        "",
        f"- Generated: `{meta['generated_at']}`",
        f"- Target: `{meta['url']}`",
        f"- Workers: `{meta['workers']}`",
        f"- Profile: `{meta['profile']}`",
        f"- Large payload: `{meta['large_mib']} MiB`",
        f"- Requests: `{summary['requests']}`",
        f"- Correct allow/block outcomes: `{summary['correct']}/{summary['requests']}`",
        f"- Wall time: `{summary['wall_seconds']:.3f} s`",
        f"- Throughput: `{summary['requests_per_second']:.2f} req/s`, `{summary['body_mib_per_second']:.2f} MiB/s`",
        f"- WAF CPU: `{summary['cgroup']['average_cpu_percent']:.1f}%` average of 200% quota",
        f"- WAF peak memory: `{summary['cgroup']['memory_peak_bytes'] / MIB:.1f} MiB / 4096 MiB`",
        f"- CPU throttled: `{summary['cgroup']['throttled_seconds']:.4f} s`",
        "",
        "## Per Case",
        "",
        "| Case | Count | Correct | Statuses | p50 ms | p95 ms | p99 ms | Guard p50 ms | Guard p99 ms |",
        "|---|---:|---:|---|---:|---:|---:|---:|---:|",
    ]
    for name, item in summary["by_case"].items():
        lat = item["latency_ms"]
        guard = item["guard_ms"]
        lines.append(
            f"| {name} | {item['count']} | {item['correct']} | `{item['statuses']}` | "
            f"{fmt(lat['p50'])} | {fmt(lat['p95'])} | {fmt(lat['p99'])} | "
            f"{fmt(guard['p50'])} | {fmt(guard['p99'])} |"
        )

    failures = [r for r in results if not r.correct]
    lines.extend(["", "## Outcome Failures", ""])
    if not failures:
        lines.append("None.")
    else:
        for result in failures:
            lines.append(
                f"- `{result.case.name}` expected {result.case.expected}, got {result.status}: "
                f"`{result.error or 'unexpected status'}`"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8081")
    parser.add_argument("--profile", choices=("correctness", "benchmark", "high-concurrency"), default="correctness")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--small-repeat", type=int, default=10)
    parser.add_argument("--large-repeat", type=int, default=1)
    parser.add_argument("--large-mib", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--seed", type=int, default=20260710)
    parser.add_argument("--container", default="ngx_json_guard_api_nginx")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/waf-perf"))
    args = parser.parse_args()

    base = urllib.parse.urlsplit(args.url)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cases = build_cases(args.output_dir / "payloads", args.large_mib)

    tasks: list[Case] = []
    if args.profile == "correctness":
        tasks = list(cases)
    elif args.profile == "high-concurrency":
        # JSON-only, many concurrent workers. Blocking temp-file reads pin
        # the NGINX worker, which shows up in p99 rather than serial p50.
        for case in cases:
            if case.group != "json":
                continue
            repeat = args.large_repeat if case.large else args.small_repeat
            tasks.extend([case] * repeat)
        random.Random(args.seed).shuffle(tasks)
    else:
        for case in cases:
            repeat = args.large_repeat if case.large else args.small_repeat
            tasks.extend([case] * repeat)
        random.Random(args.seed).shuffle(tasks)

    before = cgroup_snapshot(args.container)
    started = time.perf_counter()
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(request_once, base, case, args.timeout) for case in tasks]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(
                f"{result.case.name:30s} status={result.status} expected={result.case.expected} "
                f"ms={result.elapsed_ms:.2f} guard_us={result.guard_us} correct={result.correct}",
                flush=True,
            )
    wall_s = time.perf_counter() - started
    after = cgroup_snapshot(args.container)
    summary = summarize(results, wall_s, before, after)
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "url": args.url,
        "profile": args.profile,
        "workers": args.workers,
        "large_mib": args.large_mib,
        "seed": args.seed,
    }

    serial_results = [
        {
            "case": r.case.name,
            "group": r.case.group,
            "malicious": r.case.malicious,
            "large": r.case.large,
            "body_bytes": len(r.case.body),
            "expected": list(r.case.expected),
            "status": r.status,
            "elapsed_ms": r.elapsed_ms,
            "guard_us": r.guard_us,
            "response_bytes": r.response_bytes,
            "error": r.error,
            "correct": r.correct,
        }
        for r in results
    ]
    (args.output_dir / "results.json").write_text(
        json.dumps({"meta": meta, "summary": summary, "results": serial_results}, indent=2) + "\n"
    )
    (args.output_dir / "REPORT.md").write_text(markdown_report(meta, summary, results))

    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["correct"] == summary["requests"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
