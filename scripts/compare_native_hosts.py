#!/usr/bin/env python3
"""Compare two native ngx_json_guard benchmark result bundles."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


MIB = 1024 * 1024


def result_dir(path: Path, temporary: list[tempfile.TemporaryDirectory[str]]) -> Path:
    if path.is_dir():
        return path
    holder = tempfile.TemporaryDirectory(prefix="ngx-json-guard-compare-")
    temporary.append(holder)
    completed = subprocess.run(
        ["tar", "--zstd", "-xf", str(path), "-C", holder.name],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"cannot extract {path}: {completed.stdout}")
    candidates = list(Path(holder.name).glob("**/results.json"))
    roots = [candidate.parent for candidate in candidates if "runs" in json.loads(candidate.read_text())]
    if len(roots) != 1:
        raise SystemExit(f"expected one consolidated results.json in {path}")
    return roots[0]


def load(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    results = json.loads((root / "results.json").read_text())
    environment = json.loads((root / "environment.json").read_text())
    return results, environment


def run_map(payload: dict[str, Any]) -> dict[tuple[str, str, int], dict[str, Any]]:
    return {
        (item["meta"]["engine"], item["meta"]["suite"], item["meta"]["workers"]): item
        for item in payload["runs"]
    }


def ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host_a", type=Path)
    parser.add_argument("host_b", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("host-comparison"))
    args = parser.parse_args()

    temporary: list[tempfile.TemporaryDirectory[str]] = []
    root_a = result_dir(args.host_a, temporary)
    root_b = result_dir(args.host_b, temporary)
    payload_a, env_a = load(root_a)
    payload_b, env_b = load(root_b)
    runs_a, runs_b = run_map(payload_a), run_map(payload_b)
    cpu_a = int(env_a.get("cpu_count") or 0)
    cpu_b = int(env_b.get("cpu_count") or 0)
    cpu_ratio = ratio(cpu_b, cpu_a) if cpu_a else None

    rows = []
    case_rows = []
    for key in sorted(set(runs_a) & set(runs_b)):
        item_a, item_b = runs_a[key], runs_b[key]
        sum_a, sum_b = item_a["summary"], item_b["summary"]
        latency_a = sum_a["latency_ms"]["p50"]
        latency_b = sum_b["latency_ms"]["p50"]
        speedup = ratio(latency_a, latency_b) if latency_a is not None and latency_b is not None else None
        efficiency = ratio(speedup, cpu_ratio) if speedup is not None and cpu_ratio else None
        mib_a = sum_a["body_bytes"] / MIB
        mib_b = sum_b["body_bytes"] / MIB
        rows.append({
            "engine": key[0],
            "suite": key[1],
            "workers": key[2],
            "host_a_latency_p50_ms": latency_a,
            "host_b_latency_p50_ms": latency_b,
            "latency_speedup": speedup,
            "cpu_scaling_efficiency": efficiency,
            "host_a_cpu_seconds_per_mib": ratio(sum_a["cpu_usage_seconds"], mib_a),
            "host_b_cpu_seconds_per_mib": ratio(sum_b["cpu_usage_seconds"], mib_b),
            "host_a_peak_mib": sum_a["memory_peak_bytes"] / MIB,
            "host_b_peak_mib": sum_b["memory_peak_bytes"] / MIB,
            "host_a_correct": f"{sum_a['correct']}/{sum_a['requests']}",
            "host_b_correct": f"{sum_b['correct']}/{sum_b['requests']}",
            "host_a_noise": bool(item_a["meta"].get("noise_warning")),
            "host_b_noise": bool(item_b["meta"].get("noise_warning")),
        })
        cases_a = sum_a.get("by_case", {})
        cases_b = sum_b.get("by_case", {})
        for case_name in sorted(set(cases_a) & set(cases_b)):
            latency_case_a = cases_a[case_name]["latency_ms"]["p50"]
            latency_case_b = cases_b[case_name]["latency_ms"]["p50"]
            case_rows.append({
                "engine": key[0],
                "suite": key[1],
                "workers": key[2],
                "case": case_name,
                "host_a_latency_p50_ms": latency_case_a,
                "host_b_latency_p50_ms": latency_case_b,
                "latency_speedup": ratio(latency_case_a, latency_case_b)
                if latency_case_a is not None and latency_case_b is not None else None,
                "host_a_outcomes": cases_a[case_name]["outcomes"],
                "host_b_outcomes": cases_b[case_name]["outcomes"],
            })

    output = {
        "host_a": env_a,
        "host_b": env_b,
        "cpu_ratio_b_over_a": cpu_ratio,
        "rows": rows,
        "case_rows": case_rows,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "HOST_COMPARISON.json").write_text(json.dumps(output, indent=2) + "\n")
    lines = [
        "# Native Host Comparison",
        "",
        f"- Host A: `{env_a['server_label']}` ({cpu_a} CPUs)",
        f"- Host B: `{env_b['server_label']}` ({cpu_b} CPUs)",
        f"- CPU ratio B/A: `{fmt(cpu_ratio)}`",
        "",
        "| Engine | Suite | W | A p50 ms | B p50 ms | Speedup | Scaling efficiency | A CPU s/MiB | B CPU s/MiB | A peak MiB | B peak MiB | Correct A/B | Noise A/B |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['engine']} | {row['suite']} | {row['workers']} | "
            f"{fmt(row['host_a_latency_p50_ms'])} | {fmt(row['host_b_latency_p50_ms'])} | "
            f"{fmt(row['latency_speedup'])} | {fmt(row['cpu_scaling_efficiency'])} | "
            f"{fmt(row['host_a_cpu_seconds_per_mib'])} | {fmt(row['host_b_cpu_seconds_per_mib'])} | "
            f"{fmt(row['host_a_peak_mib'])} | {fmt(row['host_b_peak_mib'])} | "
            f"{row['host_a_correct']} / {row['host_b_correct']} | "
            f"{row['host_a_noise']} / {row['host_b_noise']} |"
        )
    lines.extend([
        "",
        "Scaling efficiency is latency speedup divided by the host CPU-count ratio.",
        "Rows flagged for shared-CPU noise should not be used for firm scaling claims.",
        "",
        "## Per-Case Latency",
        "",
        "| Engine | Suite | W | Case | A p50 ms | B p50 ms | Speedup | Outcome parity |",
        "|---|---|---:|---|---:|---:|---:|---:|",
    ])
    for row in case_rows:
        lines.append(
            f"| {row['engine']} | {row['suite']} | {row['workers']} | "
            f"{row['case']} | {fmt(row['host_a_latency_p50_ms'])} | "
            f"{fmt(row['host_b_latency_p50_ms'])} | {fmt(row['latency_speedup'])} | "
            f"{row['host_a_outcomes'] == row['host_b_outcomes']} |"
        )
    lines.extend([
        "",
    ])
    (args.output_dir / "HOST_COMPARISON.md").write_text("\n".join(lines))
    print(args.output_dir / "HOST_COMPARISON.md")


if __name__ == "__main__":
    main()
