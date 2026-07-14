#!/usr/bin/env python3
"""Generate and send large many-key JSON payloads in parallel.

This is intended for manual traffic simulation against the demo stack:

  docker compose -f docker/docker-compose.api.yml up --build -d
  ./scripts/stress_many_json_pairs.py --payloads 8 --lines 200000 --workers 4

Payloads are written to disk as pretty-printed JSON so opening the file shows
hundreds of thousands of lines. Requests are sent with curl reading from files,
which avoids keeping several large request bodies in Python memory. The default
profile expects these high-cardinality documents to hit JSON Guard's 413 token
limit before CRS inspection.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import shutil
import string
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


ATTACK_MARKER = "JG_ATTACK_MARKER_sqli"
GENERIC_SQLI = "' OR '1'='1' UNION SELECT password FROM users --"


@dataclass(frozen=True)
class Payload:
    idx: int
    path: Path
    kind: str
    expected: int | None
    bytes: int
    lines: int
    sha256: str


@dataclass(frozen=True)
class Result:
    payload: Payload
    status: int | None
    elapsed: float
    error: str | None


def rand_string(rng: random.Random, n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "_-.:"
    return "".join(rng.choice(alphabet) for _ in range(n))


def estimate_records_for_lines(target_lines: int) -> int:
    # With the object shape below and indent=2, each record contributes about
    # 24 lines. Bias upward and then trim/check actual output line count.
    return max(1, target_lines // 22)


def make_record(rng: random.Random, payload_idx: int, rec_idx: int, kind: str,
                attack_at: int | None) -> dict:
    account = rand_string(rng, 18)
    record = {
        "id": rec_idx,
        "account_id": account,
        "tenant": f"tenant-{payload_idx % 17}",
        "profile": {
            "name": f"user-{payload_idx}-{rec_idx}",
            "email": f"user{payload_idx}-{rec_idx}@example.test",
            "role": rng.choice(["reader", "writer", "admin", "auditor"]),
            "region": rng.choice(["us", "eu", "apac", "latam"]),
        },
        "metrics": {
            "score": rng.randint(0, 1000000),
            "risk": round(rng.random(), 6),
            "quota": rng.randint(1, 100000),
            "enabled": bool(rng.getrandbits(1)),
        },
        "tags": [
            rand_string(rng, 12),
            rand_string(rng, 12),
            rand_string(rng, 12),
        ],
        "attributes": {
            "k_primary": rand_string(rng, 32),
            "k_secondary": rand_string(rng, 32),
            "k_notes": rand_string(rng, 80),
        },
    }

    if attack_at is not None and rec_idx == attack_at:
        if kind == "marker_sqli":
            record["query"] = (
                f"normal prefix {ATTACK_MARKER} select * from users "
                "where id=1"
            )
        elif kind == "generic_sqli":
            record["query"] = GENERIC_SQLI
    else:
        record["query"] = f"lookup-{account}"

    return record


def build_payload(path: Path, idx: int, kind: str, target_lines: int,
                  seed: int, expected_status: int) -> Payload:
    rng = random.Random(seed + idx * 7919)
    records = estimate_records_for_lines(target_lines)
    attack_at = None
    if kind in {"marker_sqli", "generic_sqli"}:
        # Put the malicious value near the end so this exercises full-body
        # inspection, not just prefix inspection.
        attack_at = max(0, records - rng.randint(1, min(records, 25)))

    obj = {
        "payload_id": idx,
        "kind": kind,
        "target_lines": target_lines,
        "schema": "many-key-json-v1",
        "records": [
            make_record(rng, idx, rec_idx, kind, attack_at)
            for rec_idx in range(records)
        ],
        "trailer": {
            "record_count": records,
            "attack_record": attack_at,
            "end_marker": rand_string(rng, 64),
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)

    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    line_count = data.count(b"\n")
    return Payload(idx, path, kind, expected_status, len(data), line_count, digest)


def generate_payloads(args: argparse.Namespace) -> list[Payload]:
    kinds = []
    marker_count = max(0, int(args.payloads * args.marker_attack_rate))
    generic_count = max(0, int(args.payloads * args.generic_attack_rate))
    normal_count = max(0, args.payloads - marker_count - generic_count)

    kinds.extend(["normal"] * normal_count)
    kinds.extend(["marker_sqli"] * marker_count)
    kinds.extend(["generic_sqli"] * generic_count)
    while len(kinds) < args.payloads:
        kinds.append("normal")
    kinds = kinds[:args.payloads]

    rng = random.Random(args.seed)
    rng.shuffle(kinds)

    out_dir = Path(args.out_dir)
    if args.clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payloads = []
    for idx, kind in enumerate(kinds):
        path = out_dir / f"payload_{idx:03d}_{kind}_{args.lines}_lines.json"
        payload = build_payload(
            path, idx, kind, args.lines, args.seed, args.expected_status
        )
        payloads.append(payload)
        print(
            f"generated idx={idx} kind={kind} lines={payload.lines} "
            f"bytes={payload.bytes} path={payload.path}",
            flush=True,
        )

    return payloads


def send_payload(url: str, payload: Payload, timeout: int) -> Result:
    start = time.monotonic()
    cmd = [
        "curl",
        "-sS",
        "-o",
        os.devnull,
        "-w",
        "%{http_code}",
        "--max-time",
        str(timeout),
        "-X",
        "POST",
        url,
        "-H",
        "Content-Type: application/json",
        "-H",
        f"X-Body-SHA256: {payload.sha256}",
        "--data-binary",
        f"@{payload.path}",
    ]

    try:
        proc = subprocess.run(cmd, check=False, text=True,
                              capture_output=True)
        elapsed = time.monotonic() - start
        if proc.returncode != 0:
            return Result(payload, None, elapsed,
                          (proc.stderr or proc.stdout).strip())
        return Result(payload, int(proc.stdout.strip()), elapsed, None)
    except Exception as exc:  # noqa: BLE001
        return Result(payload, None, time.monotonic() - start, str(exc))


def send_all(args: argparse.Namespace, payloads: list[Payload]) -> int:
    print(
        f"sending url={args.url} payloads={len(payloads)} workers={args.workers}",
        flush=True,
    )
    started = time.monotonic()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(send_payload, args.url, payload, args.timeout)
            for payload in payloads
        ]
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            results.append(result)
            status = result.status if result.status is not None else "ERR"
            print(
                f"{status} idx={result.payload.idx} kind={result.payload.kind} "
                f"lines={result.payload.lines} bytes={result.payload.bytes} "
                f"elapsed={result.elapsed:.3f}s expected={result.payload.expected}"
                + (f" error={result.error}" if result.error else ""),
                flush=True,
            )

    elapsed = time.monotonic() - started
    failures = [
        r for r in results
        if r.payload.expected is not None and r.status != r.payload.expected
    ]
    statuses: dict[str, int] = {}
    for result in results:
        key = str(result.status) if result.status is not None else "ERR"
        statuses[key] = statuses.get(key, 0) + 1

    marker_total = sum(1 for p in payloads if p.kind == "marker_sqli")
    marker_blocked = sum(
        1 for r in results if r.payload.kind == "marker_sqli" and r.status == 403
    )
    generic_total = sum(1 for p in payloads if p.kind == "generic_sqli")
    generic_blocked = sum(
        1 for r in results if r.payload.kind == "generic_sqli" and r.status == 403
    )

    print("summary")
    print(f"  elapsed_sec={elapsed:.3f}")
    print(f"  statuses={statuses}")
    print(f"  expected_failures={len(failures)}")
    print(f"  marker_sqli_blocked={marker_blocked}/{marker_total}")
    print(
        f"  generic_sqli_blocked={generic_blocked}/{generic_total}"
    )

    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate many-key JSON payloads and send them in parallel")
    ap.add_argument("--url", default="http://127.0.0.1:8081/json/ingest")
    ap.add_argument("--out-dir", default="/tmp/jg_many_json_payloads")
    ap.add_argument("--payloads", type=int, default=8)
    ap.add_argument("--lines", type=int, default=200000)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--marker-attack-rate", type=float, default=0.25)
    ap.add_argument("--generic-attack-rate", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=4242)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument(
        "--expected-status", type=int, default=413,
        help="Expected status for every generated high-cardinality payload",
    )
    ap.add_argument("--generate-only", action="store_true")
    ap.add_argument("--reuse", action="store_true", help="Reuse existing payload files in out-dir")
    ap.add_argument("--clean", action="store_true", help="Delete out-dir before generating")
    args = ap.parse_args()

    if args.reuse:
        payloads = []
        for idx, path in enumerate(sorted(Path(args.out_dir).glob("payload_*.json"))):
            data = path.read_bytes()
            name = path.name
            if "_marker_sqli_" in name:
                kind = "marker_sqli"
                expected = args.expected_status
            elif "_generic_sqli_" in name:
                kind = "generic_sqli"
                expected = args.expected_status
            else:
                kind = "normal"
                expected = args.expected_status
            payloads.append(
                Payload(
                    idx,
                    path,
                    kind,
                    expected,
                    len(data),
                    data.count(b"\n"),
                    hashlib.sha256(data).hexdigest(),
                )
            )
    else:
        payloads = generate_payloads(args)

    if args.generate_only:
        return 0

    return send_all(args, payloads)


if __name__ == "__main__":
    raise SystemExit(main())
