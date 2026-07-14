#!/usr/bin/env python3
"""Generate and run the reproducible cross-WAF JSON benchmark."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import http.client
import json
import math
import os
import random
import re
import statistics
import subprocess
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO


MIB = 1024 * 1024
CHUNK = 1024 * 1024
SQLI = "1' OR '1'='1' UNION SELECT password FROM users--"
XSS = "<script>alert(document.domain)</script>"
CMDI = "; cat /etc/passwd; id"


@dataclass(frozen=True)
class Case:
    name: str
    method: str
    path: str
    content_type: str | None
    body_file: str | None
    body_bytes: int
    sha256: str | None
    family: str
    requirement: str
    suites: list[str]
    repeat: int = 1
    malicious: bool = False
    capability_only: bool = False


@dataclass
class Result:
    case: str
    status: int | None
    outcome: str
    elapsed_ms: float
    guard_us: int | None
    upstream_us: int | None
    reached_upstream: bool
    body_preserved: bool | None
    response_bytes: int
    error: str | None
    correct: bool


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes(path: Path, data: bytes) -> tuple[int, str]:
    if not path.exists() or path.stat().st_size != len(data):
        path.write_bytes(data)
    return path.stat().st_size, sha256_file(path)


def write_blob(path: Path, size: int, tail: str = "clean", malformed: bool = False) -> tuple[int, str]:
    prefix = b'{"kind":"blob","padding":"'
    suffix = b'","tail":' + json.dumps(tail, separators=(",", ":")).encode() + b"}"
    if malformed:
        suffix = b'","tail":' + json.dumps(tail).encode() + b",}"
    padding = size - len(prefix) - len(suffix)
    if padding < 0:
        raise ValueError(f"target {size} is too small")
    if not path.exists() or path.stat().st_size != size:
        with path.open("wb") as stream:
            stream.write(prefix)
            block = b"x" * CHUNK
            while padding:
                take = min(padding, len(block))
                stream.write(block[:take])
                padding -= take
            stream.write(suffix)
    return path.stat().st_size, sha256_file(path)


def write_chunked_blob(path: Path, size: int, values: int = 4) -> tuple[int, str]:
    prefix = b'{"chunks":["'
    separator = b'","'
    suffix = b'"]}'
    payload_bytes = size - len(prefix) - len(suffix) - len(separator) * (values - 1)
    if values < 1 or payload_bytes < values:
        raise ValueError(f"target {size} is too small for {values} values")
    base, extra = divmod(payload_bytes, values)
    if not path.exists() or path.stat().st_size != size:
        with path.open("wb") as stream:
            stream.write(prefix)
            block = b"x" * CHUNK
            for idx in range(values):
                if idx:
                    stream.write(separator)
                remaining = base + (1 if idx < extra else 0)
                while remaining:
                    take = min(remaining, len(block))
                    stream.write(block[:take])
                    remaining -= take
            stream.write(suffix)
    return path.stat().st_size, sha256_file(path)


def write_wide(path: Path, count: int, obj: bool) -> tuple[int, str]:
    if not path.exists():
        with path.open("wb") as stream:
            stream.write(b"{" if obj else b"[")
            for idx in range(count):
                if idx:
                    stream.write(b",")
                if obj:
                    stream.write(f'"k{idx}":{idx}'.encode())
                else:
                    stream.write(str(idx).encode())
            stream.write(b"}" if obj else b"]")
    return path.stat().st_size, sha256_file(path)


def write_string_value(path: Path, length: int) -> tuple[int, str]:
    expected_size = len(b'{"s":"') + length + len(b'"}')
    if not path.exists() or path.stat().st_size != expected_size:
        with path.open("wb") as stream:
            stream.write(b'{"s":"')
            block = b"s" * CHUNK
            remaining = length
            while remaining:
                take = min(remaining, len(block))
                stream.write(block[:take])
                remaining -= take
            stream.write(b'"}')
    return path.stat().st_size, sha256_file(path)


def write_token_fixture(path: Path, target_tokens: int) -> tuple[int, str]:
    inner_arrays = min(9999, target_tokens - 1)
    empty_arrays = target_tokens - 1 - inner_arrays
    if empty_arrays < 0 or math.ceil(empty_arrays / inner_arrays) > 10000:
        raise ValueError("token target cannot satisfy per-array limit")
    base, extra = divmod(empty_arrays, inner_arrays)
    with path.open("wb") as stream:
        stream.write(b"[")
        for outer in range(inner_arrays):
            if outer:
                stream.write(b",")
            stream.write(b"[")
            count = base + (1 if outer < extra else 0)
            for idx in range(count):
                if idx:
                    stream.write(b",")
                stream.write(b"[]")
            stream.write(b"]")
        stream.write(b"]")
    return path.stat().st_size, sha256_file(path)


def build_corpus(payload_dir: Path) -> list[Case]:
    payload_dir.mkdir(parents=True, exist_ok=True)
    cases: list[Case] = []

    def add(
        name: str,
        data: bytes | None,
        *,
        family: str = "valid",
        requirement: str = "normal",
        suites: tuple[str, ...] = ("correctness",),
        content_type: str | None = "application/json",
        path: str = "/json/ingest",
        method: str = "POST",
        repeat: int = 1,
        malicious: bool = False,
        capability_only: bool = False,
        existing: tuple[int, str, Path] | None = None,
    ) -> None:
        if data is not None:
            body_path = payload_dir / f"{name}.json"
            size, digest = write_bytes(body_path, data)
        elif existing is not None:
            size, digest, body_path = existing
        else:
            size, digest, body_path = 0, None, None
        cases.append(Case(
            name, method, path, content_type,
            str(body_path) if body_path else None, size, digest,
            family, requirement, list(suites), repeat, malicious, capability_only,
        ))

    add("valid_object", b'{"user":{"id":42,"name":"Ada"},"ok":true}')
    add("valid_array", b'[{"id":1},{"id":2}]')
    add("valid_nested", b'{"a":[{"b":{"c":[1,2,3]}}]}')
    add("valid_scalar", b'"top-level"')
    add("valid_whitespace", b' \r\n\t {"ok":true} \n')
    add("missing_content_type", b'{"ok":true}', content_type=None, requirement="observe", capability_only=True)
    add("parameterized_content_type", b'{"ok":true}', content_type="Application/JSON ; charset=utf-8")
    add("malformed_early", b']', family="malformed", requirement="syntax")
    add("malformed_middle", b'{"a":[1,truX,3]}', family="malformed", requirement="syntax")
    add("invalid_utf8", b'{"a":"\xf0\x28\x8c\x28"}', family="malformed", requirement="syntax")
    add("invalid_escape", b'{"a":"\\x"}', family="malformed", requirement="syntax")
    add("unpaired_surrogate", b'{"a":"\\uD800"}', family="malformed", requirement="syntax")
    add("invalid_number_leading_zero", b'{"a":01}', family="malformed", requirement="syntax")
    add("invalid_number_exponent", b'{"a":1e+}', family="malformed", requirement="syntax")
    add("trailing_document", b'{}{}', family="malformed", requirement="syntax")
    add("duplicate_key", b'{"a":1,"a":2}', requirement="observe", capability_only=True)

    for depth in (99, 100, 101):
        data = b"[" * depth + b"0" + b"]" * depth
        add(
            f"depth_{depth}", data,
            family="complexity", requirement="common_complexity" if depth > 100 else "normal",
        )

    for count in (9999, 10000, 10001, 50000):
        for obj in (False, True):
            kind = "object" if obj else "array"
            path = payload_dir / f"wide_{kind}_{count}.json"
            size, digest = write_wide(path, count, obj)
            add(
                f"wide_{kind}_{count}", None,
                family="complexity",
                requirement="common_complexity" if count > 10000 else "normal",
                existing=(size, digest, path),
            )

    for length in (4095, 4096, 4097):
        add(
            f"key_length_{length}", ('{"' + "k" * length + '":1}').encode(),
            family="complexity", requirement="guard_limit" if length > 4096 else "normal",
            capability_only=length > 4096,
        )
    for length in (255, 256, 257):
        add(
            f"number_length_{length}", ('{"n":' + "1" * length + '}').encode(),
            family="complexity", requirement="guard_limit" if length > 256 else "normal",
            capability_only=length > 256,
        )
    for length in (67108863, 67108864, 67108865):
        path = payload_dir / f"string_length_{length}.json"
        size, digest = write_string_value(path, length)
        add(
            f"string_length_{length}", None,
            family="complexity", requirement="guard_limit" if length > 67108864 else "normal",
            capability_only=length > 67108864,
            existing=(size, digest, path),
        )
    for tokens in (99999, 100000, 100001):
        path = payload_dir / f"tokens_{tokens}.json"
        size, digest = write_token_fixture(path, tokens)
        add(
            f"tokens_{tokens}", None,
            family="complexity", requirement="guard_limit" if tokens > 100000 else "normal",
            capability_only=tokens > 100000,
            existing=(size, digest, path),
        )

    for mib in (1, 10, 20, 50, 100):
        path = payload_dir / f"blob_{mib}m.json"
        item = write_blob(path, mib * MIB)
        add(
            f"blob_{mib}m", None, suites=("processor", "crs") if mib <= 20 else ("processor",),
            family="complexity" if mib == 100 else "valid",
            requirement="guard_limit" if mib == 100 else "normal",
            capability_only=mib == 100,
            repeat=5 if mib <= 20 else 3, existing=(*item, path),
        )

    chunked_100_path = payload_dir / "blob_chunked_100m.json"
    chunked_100_item = write_chunked_blob(chunked_100_path, 100 * MIB)
    add(
        "blob_chunked_100m", None, suites=("processor",), repeat=3,
        existing=(*chunked_100_item, chunked_100_path),
    )

    oversized_path = payload_dir / "blob_129m.json"
    oversized_item = write_blob(oversized_path, 129 * MIB)
    add(
        "blob_129m", None, family="body", requirement="body_limit",
        suites=("correctness",), existing=(*oversized_item, oversized_path),
    )

    malformed_path = payload_dir / "malformed_tail_20m.json"
    malformed_item = write_blob(malformed_path, 20 * MIB, malformed=True)
    add(
        "malformed_tail_20m", None, family="malformed", requirement="syntax",
        suites=("processor",), repeat=5, existing=(*malformed_item, malformed_path),
    )

    records_path = payload_dir / "records_20m.json"
    if not records_path.exists():
        with records_path.open("wb") as stream:
            stream.write(b'{"records":[')
            record = b'{"id":1,"name":"normal","active":true,"value":"abcdefghijklmnopqrstuvwxyz"},'
            remaining = 20 * MIB - len(b'{"records":[]}')
            while remaining > len(record):
                stream.write(record)
                remaining -= len(record)
            stream.write(b'{"id":2}],"padding":"')
            current = stream.tell()
            suffix = b'"}'
            stream.write(b"p" * (20 * MIB - current - len(suffix)))
            stream.write(suffix)
    add(
        "records_20m", None, family="complexity", requirement="common_complexity",
        suites=("processor",), repeat=3,
        existing=(records_path.stat().st_size, sha256_file(records_path), records_path),
    )

    for name, attack in (("sqli", SQLI), ("xss", XSS), ("cmdi", CMDI)):
        small = json.dumps({"value": attack}, separators=(",", ":")).encode()
        add(
            f"attack_{name}_small", small, family="attack", requirement="attack",
            suites=("correctness", "crs", "mixed"), repeat=10,
            malicious=True,
        )
        attack_path = payload_dir / f"attack_{name}_tail_20m.json"
        attack_item = write_blob(attack_path, 20 * MIB, tail=attack)
        add(
            f"attack_{name}_tail_20m", None, family="attack", requirement="attack",
            suites=("crs",), repeat=3, malicious=True,
            existing=(*attack_item, attack_path),
        )

    false_positive_values = {
        "fp_apostrophe": "O'Brien",
        "fp_sql_documentation": "Example SQL: SELECT name FROM users WHERE id = ?",
        "fp_html_fragment": "Use <strong>bold</strong> for emphasis",
        "fp_source_code": "if (value < 10 && value != null) return value;",
        "fp_log_message": "WARN query failed near UNION token but recovered",
        "fp_url": "https://example.test/search?q=a%27b&sort=desc",
        "fp_base64": "U0VMRUNUICogRlJPTSB1c2Vycw==",
        "fp_prompt": "Explain why ' or 1=1 is an unsafe SQL construction",
    }
    for name, value in false_positive_values.items():
        add(
            name, json.dumps({"text": value}).encode(), family="benign",
            requirement="normal", suites=("correctness", "crs", "mixed"), repeat=10,
        )

    add(
        "xml_normal", b'<order><id>42</id><item>book</item></order>',
        content_type="application/xml", path="/xml/ingest", family="valid",
        suites=("mixed",), repeat=10,
    )
    add(
        "xml_sqli", f"<request><query>{SQLI}</query></request>".encode(),
        content_type="application/xml", path="/xml/ingest", family="attack",
        requirement="attack", suites=("mixed",), repeat=10, malicious=True,
    )
    add(
        "form_normal", b"name=Ada&department=engineering",
        content_type="application/x-www-form-urlencoded", path="/form/submit",
        suites=("mixed",), repeat=10,
    )
    add(
        "form_sqli", urllib.parse.urlencode({"query": SQLI}).encode(),
        content_type="application/x-www-form-urlencoded", path="/form/submit",
        family="attack", requirement="attack", suites=("mixed",), repeat=10, malicious=True,
    )
    add(
        "web_normal", None, method="GET", path="/web/?title=Dashboard",
        content_type=None, suites=("mixed",), repeat=10,
    )
    add(
        "web_sqli", None, method="GET", path="/web/search?q=" + urllib.parse.quote(SQLI),
        content_type=None, family="attack", requirement="attack",
        suites=("mixed",), repeat=10, malicious=True,
    )

    manifest = payload_dir / "manifest.json"
    manifest.write_text(json.dumps([asdict(case) for case in cases], indent=2) + "\n")
    return cases


def load_cases(payload_dir: Path) -> list[Case]:
    manifest = payload_dir / "manifest.json"
    if not manifest.exists():
        return build_corpus(payload_dir)
    return [Case(**item) for item in json.loads(manifest.read_text())]


def command_output(command: list[str]) -> str:
    completed = subprocess.run(
        command, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    return completed.stdout


def runtime_type(engine: dict[str, Any]) -> str:
    return engine.get("runtime", {}).get("type", "docker")


def systemd_cgroup(unit: str) -> Path | None:
    control_group = command_output([
        "systemctl", "show", "--property=ControlGroup", "--value", unit,
    ]).strip()
    if not control_group or not control_group.startswith("/"):
        return None
    return Path("/sys/fs/cgroup") / control_group.lstrip("/")


def target_cgroup_value(engine: dict[str, Any], relative_path: str) -> str:
    runtime = engine.get("runtime", {})
    if runtime_type(engine) == "docker":
        container = runtime.get("id", engine.get("container", ""))
        completed = subprocess.run([
            "docker", "exec", container, "cat",
            f"/sys/fs/cgroup/{relative_path}",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        return completed.stdout.strip() if completed.returncode == 0 else ""
    cgroup = systemd_cgroup(runtime["unit"])
    if cgroup is None:
        return ""
    try:
        return (cgroup / relative_path).read_text().strip()
    except OSError:
        return ""


def target_output(engine: dict[str, Any], command: list[str]) -> str:
    runtime = engine.get("runtime", {})
    if runtime_type(engine) == "docker":
        container = runtime.get("id", engine.get("container", ""))
        return command_output(["docker", "exec", container, *command])
    return command_output(command)


def target_versions(engine: dict[str, Any]) -> dict[str, str]:
    configured = engine.get("version_commands", {})
    if configured:
        return {
            name: target_output(engine, command).strip()
            for name, command in configured.items()
        }
    if engine["family"] == "nginx":
        return {"nginx": target_output(engine, ["nginx", "-V"]).strip()}
    return {
        "caddy": target_output(engine, ["caddy", "version"]).strip(),
        "build_info": target_output(engine, ["caddy", "build-info"]).strip(),
    }


def parse_key_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    return values


def snapshot(engine: dict[str, Any]) -> dict[str, Any]:
    return {
        "cpu": parse_key_values(target_cgroup_value(engine, "cpu.stat")),
        "memory_current": int(target_cgroup_value(engine, "memory.current") or 0),
        "memory_peak": int(target_cgroup_value(engine, "memory.peak") or 0),
        "memory_events": parse_key_values(target_cgroup_value(engine, "memory.events")),
        "io_stat": target_cgroup_value(engine, "io.stat"),
        "cpu_pressure": target_cgroup_value(engine, "cpu.pressure"),
        "memory_pressure": target_cgroup_value(engine, "memory.pressure"),
        "io_pressure": target_cgroup_value(engine, "io.pressure"),
    }


def backend_snapshots(engine: dict[str, Any]) -> dict[str, dict[str, Any]]:
    snapshots = {}
    for unit in engine.get("backend_units", []):
        backend = {"runtime": {"type": "systemd", "unit": unit}}
        snapshots[unit] = snapshot(backend)
    return snapshots


def backend_http_snapshot(engine: dict[str, Any]) -> dict[str, int]:
    metrics_url = engine.get("backend_metrics_url")
    if not metrics_url:
        return {}
    parsed = urllib.parse.urlsplit(metrics_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request("GET", parsed.path or "/metrics")
        response = connection.getresponse()
        payload = json.loads(response.read())
        if response.status != 200:
            return {}
        return {
            key: int(value)
            for key, value in payload.items()
            if key != "ok" and isinstance(value, int)
        }
    except (OSError, http.client.HTTPException, json.JSONDecodeError):
        return {}
    finally:
        connection.close()


def host_cpu_snapshot() -> dict[str, int]:
    names = (
        "user", "nice", "system", "idle", "iowait", "irq", "softirq",
        "steal", "guest", "guest_nice",
    )
    try:
        values = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        return {name: int(value) for name, value in zip(names, values)}
    except (OSError, ValueError, IndexError):
        return {}


def host_cpu_summary(before: dict[str, int], after: dict[str, int]) -> dict[str, float]:
    values = {
        key: max(0, after.get(key, 0) - before.get(key, 0))
        for key in set(before) | set(after)
    }
    total = sum(values.values()) - values.get("guest", 0) - values.get("guest_nice", 0)
    idle = values.get("idle", 0) + values.get("iowait", 0)
    return {
        "busy_percent": ((total - idle) / total * 100) if total else 0,
        "steal_percent": (values.get("steal", 0) / total * 100) if total else 0,
        "iowait_percent": (values.get("iowait", 0) / total * 100) if total else 0,
    }


def stream_body(conn: http.client.HTTPConnection, stream: BinaryIO) -> None:
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        conn.send(chunk)


def expected_outcomes(case: Case, engine: dict[str, Any]) -> set[str] | None:
    if case.capability_only and case.requirement == "observe":
        return None
    if case.requirement == "normal":
        return {"allowed"}
    if case.requirement == "syntax":
        return {"malformed_rejected"} if engine["validates_json"] else {"allowed"}
    if case.requirement == "common_complexity":
        return {"complexity_rejected"} if engine["validates_json"] else {"allowed"}
    if case.requirement == "guard_limit":
        return {"complexity_rejected"} if engine["json_guard"] else None
    if case.requirement == "attack":
        return {"attack_blocked"} if engine["crs"] else {"allowed"}
    if case.requirement == "body_limit":
        return {"body_too_large"}
    return None


def classify(case: Case, status: int | None, reached: bool, error: str | None) -> str:
    if error:
        return "timeout" if "timed out" in error.lower() else "internal_error"
    if reached:
        return "allowed"
    if status is None or status >= 500:
        return "internal_error"
    if status == 413 and case.family not in {"complexity", "malformed"}:
        return "body_too_large"
    if case.family == "malformed":
        return "malformed_rejected"
    if case.family == "complexity":
        return "complexity_rejected"
    if case.malicious:
        return "attack_blocked"
    return "unexpected_block"


def request_once(base_url: str, case: Case, engine: dict[str, Any], timeout: float) -> Result:
    base = urllib.parse.urlsplit(base_url)
    started = time.perf_counter()
    conn = http.client.HTTPConnection(base.hostname, base.port, timeout=timeout)
    status: int | None = None
    guard_us: int | None = None
    upstream_us: int | None = None
    reached = False
    preserved: bool | None = None
    response_bytes = 0
    error: str | None = None
    try:
        conn.putrequest(case.method, case.path, skip_host=True)
        conn.putheader("Host", "waf.local")
        conn.putheader("Connection", "close")
        conn.putheader("X-Benchmark-Case", case.name)
        if case.content_type:
            conn.putheader("Content-Type", case.content_type)
        if case.body_file:
            conn.putheader("Content-Length", str(case.body_bytes))
        conn.endheaders()
        if case.body_file:
            with Path(case.body_file).open("rb") as stream:
                stream_body(conn, stream)
        response = conn.getresponse()
        data = response.read()
        response_bytes = len(data)
        status = response.status
        reached = response.getheader("X-Upstream-App") is not None
        raw_guard = None
        timing_header = engine.get("timing_headers", {}).get("json_guard_us")
        if timing_header:
            raw_guard = response.getheader(timing_header)
        guard_us = int(raw_guard) if raw_guard and raw_guard.isdigit() else None
        upstream_header = engine.get("timing_headers", {}).get(
            "upstream_us", "X-Upstream-Processing-Us"
        )
        raw_upstream = response.getheader(upstream_header)
        upstream_us = (
            int(raw_upstream) if raw_upstream and raw_upstream.isdigit() else None
        )
        if reached and case.sha256:
            try:
                response_obj = json.loads(data)
                preserved = (
                    response_obj.get("sha256") == case.sha256
                    and response_obj.get("body_len") == case.body_bytes
                )
            except (json.JSONDecodeError, AttributeError):
                preserved = False
    except (OSError, http.client.HTTPException) as exc:
        error = str(exc)
    finally:
        conn.close()
    outcome = classify(case, status, reached, error)
    expected = expected_outcomes(case, engine)
    correct = expected is None or outcome in expected
    if preserved is False:
        correct = False
    return Result(
        case.name, status, outcome, (time.perf_counter() - started) * 1000,
        guard_us, upstream_us, reached, preserved, response_bytes, error, correct,
    )


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def stats(values: list[float]) -> dict[str, float | None]:
    return {
        "count": len(values),
        "avg": statistics.fmean(values) if values else None,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values) if values else None,
    }


def delta(after: dict[str, int], before: dict[str, int], key: str) -> int:
    return max(0, after.get(key, 0) - before.get(key, 0))


def counter_deltas(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {
        key: max(0, after.get(key, 0) - before.get(key, 0))
        for key in sorted(set(before) | set(after))
    }


def resource_summary(
    before: dict[str, Any], after: dict[str, Any], wall: float,
) -> dict[str, Any]:
    cpu_us = delta(after["cpu"], before["cpu"], "usage_usec")
    return {
        "cpu_usage_seconds": cpu_us / 1_000_000,
        "average_cpu_percent": cpu_us / (wall * 1_000_000) * 100 if wall else 0,
        "throttled_seconds": delta(
            after["cpu"], before["cpu"], "throttled_usec"
        ) / 1_000_000,
        "memory_current_bytes": after["memory_current"],
        "memory_peak_bytes": after["memory_peak"],
        "memory_events_before": before["memory_events"],
        "memory_events_after": after["memory_events"],
        "memory_event_deltas": counter_deltas(
            after["memory_events"], before["memory_events"]
        ),
        "io_stat_before": before["io_stat"],
        "io_stat_after": after["io_stat"],
        "pressure_before": {
            "cpu": before["cpu_pressure"],
            "memory": before["memory_pressure"],
            "io": before["io_pressure"],
        },
        "pressure_after": {
            "cpu": after["cpu_pressure"],
            "memory": after["memory_pressure"],
            "io": after["io_pressure"],
        },
    }


def summarize(
    results: list[Result], cases: dict[str, Case], wall: float,
    before: dict[str, Any], after: dict[str, Any],
    backend_before: dict[str, dict[str, Any]] | None = None,
    backend_after: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    grouped: dict[str, list[Result]] = defaultdict(list)
    for result in results:
        grouped[result.case].append(result)
    body_bytes = sum(cases[result.case].body_bytes for result in results)
    resources = resource_summary(before, after, wall)
    backend_before = backend_before or {}
    backend_after = backend_after or {}
    return {
        "requests": len(results),
        "correct": sum(result.correct for result in results),
        "wall_seconds": wall,
        "body_bytes": body_bytes,
        "body_mib_per_second": body_bytes / MIB / wall if wall else 0,
        "requests_per_second": len(results) / wall if wall else 0,
        "outcomes": dict(Counter(result.outcome for result in results)),
        "statuses": dict(Counter(str(result.status) for result in results)),
        "latency_ms": stats([result.elapsed_ms for result in results if result.error is None]),
        "guard_ms": stats([
            result.guard_us / 1000 for result in results if result.guard_us is not None
        ]),
        "upstream_ms": stats([
            result.upstream_us / 1000
            for result in results if result.upstream_us is not None
        ]),
        **resources,
        "backend_resources": {
            unit: resource_summary(item, backend_after[unit], wall)
            for unit, item in backend_before.items()
            if unit in backend_after
        },
        "by_case": {
            name: {
                "count": len(items),
                "correct": sum(item.correct for item in items),
                "outcomes": dict(Counter(item.outcome for item in items)),
                "statuses": dict(Counter(str(item.status) for item in items)),
                "latency_ms": stats([item.elapsed_ms for item in items if item.error is None]),
                "guard_ms": stats([
                    item.guard_us / 1000 for item in items if item.guard_us is not None
                ]),
                "upstream_ms": stats([
                    item.upstream_us / 1000
                    for item in items if item.upstream_us is not None
                ]),
                "body_preserved": all(
                    item.body_preserved is not False for item in items
                ),
            }
            for name, items in sorted(grouped.items())
        },
    }


def extract_rule_ids(log_text: str) -> list[str]:
    patterns = (
        r'\[id "(\d+)"\]',
        r'"rule_id"\s*:\s*"?(\d+)"?',
        r'"ruleId"\s*:\s*"?(\d+)"?',
        r'\bid[:= ]+(\d{5,})\b',
    )
    found: set[str] = set()
    for pattern in patterns:
        found.update(re.findall(pattern, log_text))
    return sorted(found, key=int)


def target_file(engine: dict[str, Any], path: str) -> str:
    if runtime_type(engine) == "docker":
        return target_output(engine, ["cat", path])
    try:
        return Path(path).read_text(errors="replace")
    except OSError as exc:
        return f"unable to read {path}: {exc}\n"


def target_logs(engine: dict[str, Any], since_epoch: int) -> dict[str, str]:
    runtime = engine.get("runtime", {})
    if runtime_type(engine) == "docker":
        container = runtime.get("id", engine.get("container", ""))
        primary = command_output(["docker", "logs", container])
        name = "docker"
    else:
        primary = command_output([
            "journalctl", "--no-pager", "--output=short-iso",
            "--unit", runtime["unit"], "--since", f"@{since_epoch}",
        ])
        name = "journal"
    captured = {name: primary}
    for log_name, path in engine.get("log_locations", {}).items():
        captured[log_name] = target_file(engine, path)
    return captured


def run_suite(args: argparse.Namespace) -> int:
    engines = json.loads(args.engines.read_text())
    engine = engines[args.engine]
    all_cases = load_cases(args.payload_dir)
    selected = [case for case in all_cases if args.suite in case.suites]
    if args.case_regex:
        regex = re.compile(args.case_regex)
        selected = [case for case in selected if regex.search(case.name)]
    if args.quick:
        selected = [case for case in selected if case.body_bytes <= 20 * MIB]

    tasks: list[Case] = []
    if args.suite == "correctness":
        tasks = selected
    else:
        for case in selected:
            repeat = min(case.repeat, args.max_repeat) if args.max_repeat else case.repeat
            tasks.extend([case] * repeat)
        random.Random(args.seed).shuffle(tasks)

    if not tasks:
        raise SystemExit(f"no cases selected for suite {args.suite}")

    log_since = int(time.time())
    warmups = selected if args.warmup else []
    for case in warmups:
        result = request_once(engine["base_url"], case, engine, args.timeout)
        print(f"warmup {case.name}: {result.status} {result.outcome}", flush=True)

    before = snapshot(engine)
    backend_before = backend_snapshots(engine)
    backend_http_before = backend_http_snapshot(engine)
    host_before = host_cpu_snapshot()
    started = time.perf_counter()
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(request_once, engine["base_url"], case, engine, args.timeout)
            for case in tasks
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(
                f"{result.case:32s} status={result.status} outcome={result.outcome:22s} "
                f"ms={result.elapsed_ms:.2f} guard_us={result.guard_us} "
                f"upstream_us={result.upstream_us} correct={result.correct}",
                flush=True,
            )
    wall = time.perf_counter() - started
    host_after = host_cpu_snapshot()
    after = snapshot(engine)
    backend_after = backend_snapshots(engine)
    backend_http_after = backend_http_snapshot(engine)
    case_map = {case.name: case for case in all_cases}
    summary = summarize(
        results, case_map, wall, before, after, backend_before, backend_after,
    )
    if runtime_type(engine) == "systemd":
        cpu = host_cpu_summary(host_before, host_after)
        summary["host"] = {
            "cpu": cpu,
            "noise_warning": cpu["steal_percent"] > 5.0,
            "noise_threshold_steal_percent": 5.0,
            "measurement": "request window",
        }
    summary["backend_http_metrics"] = {
        "before": backend_http_before,
        "after": backend_http_after,
        "deltas": counter_deltas(backend_http_after, backend_http_before),
    }

    captured_logs = target_logs(engine, log_since)
    rule_ids = extract_rule_ids("\n".join(captured_logs.values()))
    versions = target_versions(engine)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "engine": args.engine,
        "engine_config": engine,
        "suite": args.suite,
        "workers": args.workers,
        "timeout": args.timeout,
        "seed": args.seed,
        "warmup": args.warmup,
        "quick": args.quick,
        "max_repeat": args.max_repeat,
        "case_regex": args.case_regex,
        "selected_cases": [case.name for case in selected],
        "routes": engine.get("routes", {}),
        "timing_headers": engine.get("timing_headers", {}),
        "log_locations": engine.get("log_locations", {}),
        "runtime": runtime_type(engine),
        "noise_warning": summary.get("host", {}).get("noise_warning", False),
        "target_versions": versions,
        "container_versions": versions,
        "matched_rule_ids": rule_ids,
    }
    payload = {
        "meta": meta,
        "summary": summary,
        "results": [asdict(result) for result in results],
    }
    (args.output_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n")
    for name, content in captured_logs.items():
        (args.output_dir / f"{name}.log").write_text(content)
    with (args.output_dir / "results.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        writer.writerows(asdict(result) for result in results)
    (args.output_dir / "REPORT.md").write_text(single_report(meta, summary))
    print(
        "summary "
        f"correct={summary['correct']}/{summary['requests']} "
        f"wall_s={summary['wall_seconds']:.3f} "
        f"mib_s={summary['body_mib_per_second']:.2f} "
        f"cpu_pct={summary['average_cpu_percent']:.1f} "
        f"peak_mib={summary['memory_peak_bytes'] / MIB:.1f}",
        flush=True,
    )
    return 0 if summary["correct"] == summary["requests"] else 1


def fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def single_report(meta: dict[str, Any], summary: dict[str, Any]) -> str:
    lines = [
        "# Cross-WAF Benchmark Run",
        "",
        f"- Engine: `{meta['engine']}`",
        f"- Suite: `{meta['suite']}`",
        f"- Workers: `{meta['workers']}`",
        f"- Correct: `{summary['correct']}/{summary['requests']}`",
        f"- Wall: `{summary['wall_seconds']:.3f} s`",
        f"- Throughput: `{summary['body_mib_per_second']:.2f} MiB/s`",
        f"- CPU: `{summary['average_cpu_percent']:.1f}%`",
        f"- Peak memory: `{summary['memory_peak_bytes'] / MIB:.1f} MiB`",
        f"- Upstream processing p50: `{fmt(summary['upstream_ms']['p50'])} ms`",
        f"- Outcomes: `{summary['outcomes']}`",
        f"- Matched rule IDs: `{meta['matched_rule_ids']}`",
        "",
        "| Case | Correct | Outcomes | p50 ms | p95 ms | Guard p50 ms | Upstream p50 ms | Preserved |",
        "|---|---:|---|---:|---:|---:|---:|---:|",
    ]
    for name, item in summary["by_case"].items():
        lines.append(
            f"| {name} | {item['correct']}/{item['count']} | `{item['outcomes']}` | "
            f"{fmt(item['latency_ms']['p50'])} | {fmt(item['latency_ms']['p95'])} | "
            f"{fmt(item['guard_ms']['p50'])} | {fmt(item['upstream_ms']['p50'])} | "
            f"{item['body_preserved']} |"
        )
    if summary["backend_resources"]:
        lines.extend(["", "## Backend Cgroups", ""])
        for unit, resources in summary["backend_resources"].items():
            lines.append(
                f"- `{unit}`: CPU `{resources['cpu_usage_seconds']:.3f} s`, "
                f"peak memory `{resources['memory_peak_bytes'] / MIB:.1f} MiB`"
            )
    lines.append("")
    return "\n".join(lines)


def comparison_report(args: argparse.Namespace) -> int:
    runs = []
    for result_file in sorted(args.results_root.glob("**/results.json")):
        try:
            item = json.loads(result_file.read_text())
        except json.JSONDecodeError:
            continue
        if "meta" not in item or "summary" not in item or "results" not in item:
            continue
        item["path"] = str(result_file.parent)
        runs.append(item)
    if not runs:
        raise SystemExit("no result files found")

    runtimes = {run["meta"].get("runtime", "docker") for run in runs}
    if runtimes == {"systemd"}:
        environment_lines = [
            "All WAF targets ran natively as dedicated systemd services using the",
            "host's available CPU and memory. Raw HTTP statuses are retained;",
        ]
    else:
        environment_lines = [
            "Docker WAF targets were constrained to 2 vCPU / 4 GiB. Raw HTTP statuses",
            "are retained;",
        ]
    lines = [
        "# Cross-WAF JSON Processing Comparison",
        "",
        *environment_lines,
        "normalized outcomes distinguish a WAF rejection from a body",
        "that reached the upstream and was rejected there.",
        "",
        "| Engine | Suite | Workers | Correct | MiB/s | CPU % | Peak MiB | p50 ms | p95 ms | Upstream p50 ms | Steal % | Noisy |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for run in runs:
        meta, summary = run["meta"], run["summary"]
        steal = summary.get("host", {}).get("cpu", {}).get("steal_percent")
        lines.append(
            f"| {meta['engine']} | {meta['suite']} | {meta['workers']} | {summary['correct']}/{summary['requests']} | "
            f"{summary['body_mib_per_second']:.2f} | {summary['average_cpu_percent']:.1f} | "
            f"{summary['memory_peak_bytes'] / MIB:.1f} | "
            f"{fmt(summary['latency_ms']['p50'])} | {fmt(summary['latency_ms']['p95'])} | "
            f"{fmt(summary.get('upstream_ms', {}).get('p50'))} | {fmt(steal)} | "
            f"{meta.get('noise_warning', False)} |"
        )

    by_key = {(run["meta"]["engine"], run["meta"]["suite"]): run for run in runs}
    lines.extend(["", "## JSON Guard Evaluation", ""])
    guard_run = by_key.get(("nginx-guard-modsecurity-crs", "crs"))
    modsec_run = by_key.get(("nginx-modsecurity-crs", "crs"))
    if guard_run and modsec_run:
        guard_case = guard_run["summary"]["by_case"].get("blob_20m")
        modsec_case = modsec_run["summary"]["by_case"].get("blob_20m")
        if guard_case and modsec_case:
            guard_ms = guard_case["latency_ms"]["p50"]
            modsec_ms = modsec_case["latency_ms"]["p50"]
            overhead = guard_ms - modsec_ms
            pct = overhead / modsec_ms * 100 if modsec_ms else 0
            exact = guard_case["guard_ms"]["p50"]
            exact_pct = exact / modsec_ms * 100 if exact is not None and modsec_ms else None
            lines.append(
                f"Accepted 20 MiB full-CRS end-to-end median differential: "
                f"`{overhead:.2f} ms` (`{pct:.2f}%`). This differential includes run "
                "noise and must not be interpreted as Guard acceleration when negative."
            )
            lines.append(
                f"The exact Guard timer reports `{fmt(exact)} ms`, or "
                f"`{fmt(exact_pct)}%` of the ModSecurity-only full-CRS median."
            )
            passed = (
                exact is not None and exact_pct is not None
                and exact < 250 and exact_pct < 10
            )
            lines.append(
                "Accepted-body Guard criterion (exact timer <250 ms and <10% of "
                "ModSecurity-only full-CRS latency): "
                + ("**PASS**" if passed else "**FAIL**")
                + "."
            )
        guard_cases = guard_run["summary"]["by_case"]
        modsec_cases = modsec_run["summary"]["by_case"]
        common_cases = sorted(set(guard_cases) & set(modsec_cases))
        decision_mismatches = [
            case_name for case_name in common_cases
            if guard_cases[case_name]["outcomes"] != modsec_cases[case_name]["outcomes"]
            or guard_cases[case_name]["statuses"] != modsec_cases[case_name]["statuses"]
        ]
        if decision_mismatches:
            lines.append(
                "Full-CRS normalized outcome/status mismatches: "
                + ", ".join(f"`{name}`" for name in decision_mismatches)
                + "."
            )
        else:
            lines.append(
                f"Full-CRS normalized outcomes and raw statuses matched for all "
                f"`{len(common_cases)}` common cases."
            )
    else:
        lines.append("Full CRS pair not present; accepted-body overhead is not yet evaluated.")

    processor_engines = [
        "nginx-baseline",
        "nginx-guard",
        "nginx-modsecurity-processor",
        "nginx-guard-modsecurity-processor",
        "coraza-processor",
    ]
    processor_candidates = [
        "blob_1m", "blob_10m", "blob_20m", "malformed_tail_20m", "records_20m",
        "blob_50m", "blob_100m", "blob_chunked_100m",
    ]
    processor_cases = [
        case_name for case_name in processor_candidates
        if any(
            case_name in run["summary"]["by_case"]
            for (engine, suite), run in by_key.items()
            if suite == "processor"
        )
    ]
    if processor_cases:
        lines.extend([
            "",
            "### Processor-Only Case Medians",
            "",
            "These medians isolate structural admission from full CRS rule evaluation.",
            "",
            "| Engine | " + " | ".join(processor_cases) + " |",
            "|---|" + "---:|" * len(processor_cases),
        ])
        for engine in processor_engines:
            run = by_key.get((engine, "processor"))
            values = []
            for case_name in processor_cases:
                item = run["summary"]["by_case"].get(case_name) if run else None
                values.append(fmt(item["latency_ms"]["p50"] if item else None))
            lines.append(f"| {engine} | " + " | ".join(values) + " |")

    modsec_processor = by_key.get(("nginx-modsecurity-processor", "processor"))
    guard_processor = by_key.get(("nginx-guard-modsecurity-processor", "processor"))
    material_lines = []
    material_pass = False
    if modsec_processor and guard_processor:
        for case_name, label in (
            ("malformed_tail_20m", "Malformed JSON at the 20 MiB tail"),
            ("records_20m", "20 MiB high-cardinality JSON"),
        ):
            baseline = modsec_processor["summary"]["by_case"].get(case_name)
            guarded = guard_processor["summary"]["by_case"].get(case_name)
            if baseline and guarded:
                baseline_ms = baseline["latency_ms"]["p50"]
                guarded_ms = guarded["latency_ms"]["p50"]
                reduction = (baseline_ms - guarded_ms) / baseline_ms * 100
                material_pass = material_pass or reduction >= 20
                material_lines.append(
                    f"- {label}: `{baseline_ms:.2f} ms` with ModSecurity's JSON "
                    f"processor versus `{guarded_ms:.2f} ms` with Guard first "
                    f"(`{reduction:.1f}%` lower median latency)."
                )
        baseline = modsec_processor["summary"]["by_case"].get("blob_20m")
        guarded = guard_processor["summary"]["by_case"].get("blob_20m")
        if baseline and guarded:
            baseline_ms = baseline["latency_ms"]["p50"]
            guarded_ms = guarded["latency_ms"]["p50"]
            increase = (guarded_ms - baseline_ms) / baseline_ms * 100
            material_lines.append(
                f"- Accepted 20 MiB processor-only cost: `{baseline_ms:.2f} ms` "
                f"versus `{guarded_ms:.2f} ms` (`{increase:.1f}%` higher end-to-end) "
                "because both parsers examine the accepted body."
            )
    if material_lines:
        material_lines.append(
            "- Abusive-body improvement criterion (at least 20% lower rejection "
            "latency for one class): "
            + ("**PASS**." if material_pass else "**FAIL**.")
        )
        lines.extend(["", "### Material Rejection Results", "", *material_lines])

    limit_cases = [
        "string_length_67108863", "string_length_67108864",
        "string_length_67108865", "blob_129m",
    ]
    if any(
        case_name in run["summary"]["by_case"]
        for run in runs for case_name in limit_cases
    ):
        lines.extend([
            "",
            "### Large-Body Boundaries",
            "",
            "The 100 MiB single-value case exceeds Guard's retained 64 MiB string "
            "limit. `blob_chunked_100m` verifies acceptance of a 100 MiB document "
            "whose four values each remain below that limit.",
            "",
            "| Engine | 64 MiB - 1 | 64 MiB | 64 MiB + 1 | 129 MiB body |",
            "|---|---|---|---|---|",
        ])
        for engine in processor_engines:
            run = by_key.get((engine, "correctness"))
            if not run:
                continue
            values = []
            for case_name in limit_cases:
                item = run["summary"]["by_case"].get(case_name)
                if not item:
                    values.append("-")
                    continue
                outcome = next(iter(item["outcomes"]), "-")
                values.append(f"{outcome} ({fmt(item['latency_ms']['p50'])} ms)")
            lines.append(f"| {engine} | " + " | ".join(values) + " |")

    lines.extend(["", "## Correctness Discrepancies", ""])
    discrepancies = []
    for run in runs:
        if run["meta"]["suite"] != "correctness":
            continue
        failed: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for result in run["results"]:
            if not result["correct"]:
                failed[result["case"]].add((result["outcome"], str(result["status"])))
        for case_name, outcomes in sorted(failed.items()):
            rendered = ", ".join(
                f"{outcome} (HTTP {status})" for outcome, status in sorted(outcomes)
            )
            discrepancies.append((run["meta"]["engine"], case_name, rendered))
    if discrepancies:
        lines.extend([
            "| Engine | Case | Observed |",
            "|---|---|---|",
        ])
        for engine, case_name, observed in discrepancies:
            lines.append(f"| {engine} | {case_name} | {observed} |")
    else:
        lines.append("No correctness discrepancies were recorded.")

    preservation_failures = [
        (run["meta"]["engine"], result["case"])
        for run in runs
        for result in run["results"]
        if result["reached_upstream"] and result["body_preserved"] is False
    ]
    lines.extend(["", "## Integrity And Scope", ""])
    if preservation_failures:
        lines.append(
            "Body hash/length verification failed for: "
            + ", ".join(f"`{engine}/{case}`" for engine, case in preservation_failures)
            + "."
        )
    else:
        lines.append(
            "Every body that reached an upstream with a known fixture hash retained "
            "its original byte length and SHA-256 digest."
        )
    crs_counts = {
        run["meta"]["engine"]: run["summary"]["requests"]
        for run in runs if run["meta"]["suite"] == "crs"
    }
    if crs_counts and len(set(crs_counts.values())) > 1:
        rendered = ", ".join(f"`{key}={value}`" for key, value in sorted(crs_counts.items()))
        lines.append(
            "CRS suite request counts differ (" + rendered + "). Aggregate CRS "
            "throughput rows are therefore not direct rankings; compare identical "
            "per-case medians instead."
        )
    lines.extend([
        "",
        "Capability-only cases are not counted as failures for engines that do not expose",
        "the corresponding key/string/number/token limit. This corpus is a processing",
        "comparison, not a general WAF detection-rate or false-positive benchmark.",
        "Cgroup peak memory is meaningful only when the orchestrator recreates the active",
        "WAF target before the suite; both checked-in orchestrators do this.",
        "",
    ])
    output = args.output or (args.results_root / "COMPARISON.md")
    output.write_text("\n".join(lines))
    consolidated = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results_root": str(args.results_root),
        "runs": [
            {"path": run["path"], "meta": run["meta"], "summary": run["summary"]}
            for run in runs
        ],
    }
    (args.results_root / "results.json").write_text(
        json.dumps(consolidated, indent=2) + "\n"
    )
    with (args.results_root / "results.csv").open("w", newline="") as stream:
        fieldnames = [
            "engine", "suite", "workers", "requests", "correct",
            "wall_seconds", "body_mib_per_second", "requests_per_second",
            "cpu_usage_seconds", "average_cpu_percent", "memory_peak_bytes",
            "latency_p50_ms", "latency_p95_ms", "guard_p50_ms",
            "upstream_p50_ms", "runtime", "path",
            "host_steal_percent", "noise_warning",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for run in runs:
            meta, summary = run["meta"], run["summary"]
            writer.writerow({
                "engine": meta["engine"],
                "suite": meta["suite"],
                "workers": meta["workers"],
                "requests": summary["requests"],
                "correct": summary["correct"],
                "wall_seconds": summary["wall_seconds"],
                "body_mib_per_second": summary["body_mib_per_second"],
                "requests_per_second": summary["requests_per_second"],
                "cpu_usage_seconds": summary["cpu_usage_seconds"],
                "average_cpu_percent": summary["average_cpu_percent"],
                "memory_peak_bytes": summary["memory_peak_bytes"],
                "latency_p50_ms": summary["latency_ms"]["p50"],
                "latency_p95_ms": summary["latency_ms"]["p95"],
                "guard_p50_ms": summary["guard_ms"]["p50"],
                "upstream_p50_ms": summary.get("upstream_ms", {}).get("p50"),
                "runtime": meta.get("runtime", "docker"),
                "path": run["path"],
                "host_steal_percent": summary.get("host", {}).get("cpu", {}).get("steal_percent"),
                "noise_warning": meta.get("noise_warning", False),
            })
    print(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--engines", type=Path,
        default=Path(__file__).resolve().parents[1] / "benchmark" / "engines.json",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate")
    generate.add_argument("--payload-dir", type=Path, required=True)

    run = sub.add_parser("run")
    run.add_argument("--engine", required=True)
    run.add_argument("--suite", choices=("correctness", "processor", "crs", "mixed"), required=True)
    run.add_argument("--payload-dir", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--workers", type=int, default=1)
    run.add_argument("--timeout", type=float, default=300)
    run.add_argument("--seed", type=int, default=20260710)
    run.add_argument("--max-repeat", type=int, default=0)
    run.add_argument("--case-regex")
    run.add_argument("--warmup", action="store_true")
    run.add_argument("--quick", action="store_true")

    report = sub.add_parser("report")
    report.add_argument("--results-root", type=Path, required=True)
    report.add_argument("--output", type=Path)

    args = parser.parse_args()
    if args.command == "generate":
        cases = build_corpus(args.payload_dir)
        print(f"generated {len(cases)} cases in {args.payload_dir}")
        return 0
    if args.command == "run":
        return run_suite(args)
    return comparison_report(args)


if __name__ == "__main__":
    raise SystemExit(main())
