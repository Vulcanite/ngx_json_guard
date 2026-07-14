#!/usr/bin/env python3
"""Capture and annotate host-level metrics for native benchmark runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any


PROC_CPU_FIELDS = (
    "user", "nice", "system", "idle", "iowait", "irq", "softirq",
    "steal", "guest", "guest_nice",
)


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return ""


def proc_cpu() -> dict[str, int]:
    fields = read_text("/proc/stat").splitlines()[0].split()[1:]
    return {
        name: int(value)
        for name, value in zip(PROC_CPU_FIELDS, fields, strict=False)
    }


def netdev() -> dict[str, dict[str, int]]:
    result = {}
    for line in read_text("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        fields = [int(value) for value in values.split()]
        result[name.strip()] = {
            "rx_bytes": fields[0],
            "rx_packets": fields[1],
            "tx_bytes": fields[8],
            "tx_packets": fields[9],
        }
    return result


def snapshot() -> dict[str, Any]:
    return {
        "timestamp": time.time(),
        "cpu": proc_cpu(),
        "loadavg": read_text("/proc/loadavg"),
        "meminfo": read_text("/proc/meminfo"),
        "pressure": {
            name: read_text(f"/proc/pressure/{name}")
            for name in ("cpu", "memory", "io")
        },
        "netdev": netdev(),
        "diskstats": read_text("/proc/diskstats"),
    }


def cpu_deltas(before: dict[str, Any], after: dict[str, Any]) -> dict[str, float]:
    deltas = {
        key: max(0, after["cpu"].get(key, 0) - before["cpu"].get(key, 0))
        for key in set(before["cpu"]) | set(after["cpu"])
    }
    total = sum(deltas.values()) - deltas.get("guest", 0) - deltas.get("guest_nice", 0)
    idle = deltas.get("idle", 0) + deltas.get("iowait", 0)
    return {
        "total_ticks": total,
        "busy_percent": ((total - idle) / total * 100) if total else 0,
        "steal_percent": (deltas.get("steal", 0) / total * 100) if total else 0,
        "iowait_percent": (deltas.get("iowait", 0) / total * 100) if total else 0,
    }


def net_deltas(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, int]]:
    result = {}
    for name in sorted(set(before["netdev"]) | set(after["netdev"])):
        old = before["netdev"].get(name, {})
        new = after["netdev"].get(name, {})
        result[name] = {
            key: max(0, new.get(key, 0) - old.get(key, 0))
            for key in ("rx_bytes", "rx_packets", "tx_bytes", "tx_packets")
        }
    return result


def annotate(results: Path, before_path: Path, after_path: Path) -> None:
    payload = json.loads(results.read_text())
    before = json.loads(before_path.read_text())
    after = json.loads(after_path.read_text())
    broad_cpu = cpu_deltas(before, after)
    exact_host = payload["summary"].get("host", {})
    cpu = exact_host.get("cpu", broad_cpu)
    host = {
        "duration_seconds": max(0, after["timestamp"] - before["timestamp"]),
        "cpu": cpu,
        "network_deltas": net_deltas(before, after),
        "loadavg_before": before["loadavg"],
        "loadavg_after": after["loadavg"],
        "pressure_before": before["pressure"],
        "pressure_after": after["pressure"],
        "noise_warning": cpu["steal_percent"] > 5.0,
        "noise_threshold_steal_percent": 5.0,
        "measurement": exact_host.get("measurement", "suite process window"),
        "broad_process_window_cpu": broad_cpu,
    }
    payload["summary"]["host"] = host
    payload["meta"]["noise_warning"] = host["noise_warning"]
    results.write_text(json.dumps(payload, indent=2) + "\n")

    report = results.parent / "REPORT.md"
    if report.exists():
        with report.open("a") as stream:
            stream.write("\n## Host Telemetry\n\n")
            stream.write(f"- Host CPU busy: `{cpu['busy_percent']:.2f}%`\n")
            stream.write(f"- Host CPU steal: `{cpu['steal_percent']:.2f}%`\n")
            stream.write(f"- Host I/O wait: `{cpu['iowait_percent']:.2f}%`\n")
            stream.write(
                f"- Shared-CPU noise warning (>5% steal): "
                f"`{host['noise_warning']}`\n"
            )


def command(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    return completed.stdout.strip()


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digitalocean_region() -> str | None:
    try:
        with urllib.request.urlopen(
            "http://169.254.169.254/metadata/v1/region", timeout=1
        ) as response:
            return response.read(128).decode("ascii", "replace").strip() or None
    except OSError:
        return None


def environment(output_dir: Path, server_label: str, repo: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    meminfo = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meminfo[key] = value.strip()
    cpu_model = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    binaries = {
        "nginx": Path("/opt/ngx-json-guard/nginx/sbin/nginx"),
        "json_guard_module": Path(
            "/opt/ngx-json-guard/nginx/modules/ngx_http_json_guard_module.so"
        ),
        "modsecurity_module": Path(
            "/opt/ngx-json-guard/nginx/modules/ngx_http_modsecurity_module.so"
        ),
        "caddy": Path("/opt/ngx-json-guard/bin/caddy"),
    }
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "server_label": server_label,
        "hostname": socket.gethostname(),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "cpu_model": cpu_model,
        "memory_total": meminfo.get("MemTotal"),
        "swap_total": meminfo.get("SwapTotal"),
        "digitalocean_region": digitalocean_region(),
        "git_revision": command(["git", "rev-parse", "HEAD"], repo),
        "git_status": command(["git", "status", "--short"], repo),
        "binary_sha256": {name: sha256(path) for name, path in binaries.items()},
        "nginx_version": command([str(binaries["nginx"]), "-V"]),
        "caddy_version": command([str(binaries["caddy"]), "version"]),
        "caddy_build_info": command([str(binaries["caddy"]), "build-info"]),
    }
    (output_dir / "environment.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Native Benchmark Environment",
        "",
        f"- Label: `{server_label}`",
        f"- Hostname: `{payload['hostname']}`",
        f"- Platform: `{payload['platform']}`",
        f"- CPU: `{payload['cpu_count']} x {cpu_model}`",
        f"- Memory: `{payload['memory_total']}`",
        f"- Swap: `{payload['swap_total']}`",
        f"- DigitalOcean region: `{payload['digitalocean_region'] or 'not detected'}`",
        f"- Git revision: `{payload['git_revision'] or 'not a git checkout'}`",
        "",
        "## Binary SHA-256",
        "",
    ]
    lines.extend(f"- `{name}`: `{value}`" for name, value in payload["binary_sha256"].items())
    (output_dir / "ENVIRONMENT.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--output", type=Path, required=True)
    note = sub.add_parser("annotate")
    note.add_argument("--results", type=Path, required=True)
    note.add_argument("--before", type=Path, required=True)
    note.add_argument("--after", type=Path, required=True)
    env = sub.add_parser("environment")
    env.add_argument("--output-dir", type=Path, required=True)
    env.add_argument("--server-label", required=True)
    env.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "snapshot":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot(), indent=2) + "\n")
    elif args.command == "annotate":
        annotate(args.results, args.before, args.after)
    else:
        environment(args.output_dir, args.server_label, args.repo)


if __name__ == "__main__":
    main()
