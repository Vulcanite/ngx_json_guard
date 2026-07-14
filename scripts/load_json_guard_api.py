#!/usr/bin/env python3
"""Parallel JSON load driver for the protected demo API.

Generates mixed JSON request bodies, including large 20 MiB payloads and
interleaved SQL injection probes. The API stack runs pinned OWASP CRS rules.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import random
import string
import time
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Case:
    idx: int
    name: str
    size_bytes: int
    attack: str
    expected: int | None


@dataclass(frozen=True)
class Result:
    case: Case
    status: int | None
    elapsed: float
    response_len: int
    error: str | None


def filler(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    rng = random.Random(length)
    return "".join(rng.choice(alphabet) for _ in range(length))


def make_body(case: Case) -> bytes:
    base = {
        "request_id": case.idx,
        "case": case.name,
        "meta": {
            "size_target": case.size_bytes,
            "attack": case.attack,
        },
        "values": [1, True, None, "ok"],
    }

    if case.attack == "marker_sqli":
        base["query"] = "normal search"
        tail_probe = "JG_ATTACK_MARKER_sqli select * from users where id=1"
    elif case.attack == "generic_sqli":
        base["query"] = "normal search"
        tail_probe = "' OR '1'='1' UNION SELECT password FROM users --"
    else:
        base["query"] = "normal search"
        tail_probe = None

    if tail_probe is not None:
        base["tail_probe"] = tail_probe

    encoded = json.dumps(base, separators=(",", ":")).encode("utf-8")
    overhead = len(encoded) + len(',"padding":""')
    pad_len = max(0, case.size_bytes - overhead)
    base["padding"] = filler(pad_len)
    if tail_probe is not None:
        # Reinsert after padding so the attack string sits near the tail.
        del base["tail_probe"]
        base["tail_probe"] = tail_probe
    return json.dumps(base, separators=(",", ":")).encode("utf-8")


def post(url: str, case: Case, timeout: float) -> Result:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    body = make_body(case)
    start = time.monotonic()
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port
    host = parsed.hostname or "127.0.0.1"

    try:
        conn = conn_cls(host, port, timeout=timeout)
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Body-SHA256": hashlib.sha256(body).hexdigest(),
            },
        )
        resp = conn.getresponse()
        data = resp.read()
        elapsed = time.monotonic() - start
        conn.close()
        return Result(case, resp.status, elapsed, len(data), None)
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - start
        return Result(case, None, elapsed, 0, str(exc))


def build_cases(args: argparse.Namespace) -> list[Case]:
    sizes = [
        1024,
        64 * 1024,
        1024 * 1024,
        5 * 1024 * 1024,
    ]
    cases: list[Case] = []

    for i in range(args.requests):
        size = sizes[i % len(sizes)]
        cases.append(Case(i, f"valid-{size}", size, "none", 200))

    start = len(cases)
    for i in range(args.large_count):
        cases.append(
            Case(
                start + i,
                f"valid-{args.large_size_mb}mb-{i}",
                args.large_size_mb * 1024 * 1024,
                "none",
                200,
            )
        )

    start = len(cases)
    for i in range(args.attack_count):
        cases.append(
            Case(
                start + i,
                f"marker-sqli-{i}",
                args.attack_size_kb * 1024,
                "marker_sqli",
                403,
            )
        )
        cases.append(
            Case(
                start + args.attack_count + i,
                f"generic-sqli-{i}",
                args.attack_size_kb * 1024,
                "generic_sqli",
                403,
            )
        )

    start = len(cases)
    for i in range(args.large_attack_count):
        cases.append(
            Case(
                start + i,
                f"large-marker-sqli-{i}",
                args.large_size_mb * 1024 * 1024,
                "marker_sqli",
                403,
            )
        )
        cases.append(
            Case(
                start + args.large_attack_count + i,
                f"large-generic-sqli-{i}",
                args.large_size_mb * 1024 * 1024,
                "generic_sqli",
                403,
            )
        )

    random.Random(args.seed).shuffle(cases)
    return cases


def main() -> int:
    ap = argparse.ArgumentParser(description="Parallel load test for ngx_json_guard demo API")
    ap.add_argument("--url", default="http://127.0.0.1:8081/json/ingest")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--requests", type=int, default=16, help="Non-large valid requests")
    ap.add_argument("--large-count", type=int, default=6)
    ap.add_argument("--large-size-mb", type=int, default=20)
    ap.add_argument("--attack-count", type=int, default=6)
    ap.add_argument("--large-attack-count", type=int, default=2)
    ap.add_argument("--attack-size-kb", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    cases = build_cases(args)
    print(
        f"target={args.url} total={len(cases)} workers={args.workers} "
        f"large={args.large_count}x{args.large_size_mb}MiB "
        f"attacks={(args.attack_count + args.large_attack_count) * 2}",
        flush=True,
    )

    started = time.monotonic()
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(post, args.url, case, args.timeout) for case in cases]
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            results.append(result)
            status = result.status if result.status is not None else "ERR"
            expected = "" if result.case.expected is None else f" expected={result.case.expected}"
            print(
                f"{status} {result.case.name} attack={result.case.attack} "
                f"bytes={result.case.size_bytes} elapsed={result.elapsed:.3f}s{expected}"
                + (f" error={result.error}" if result.error else ""),
                flush=True,
            )

    elapsed = time.monotonic() - started
    failures = 0
    marker_blocked = 0
    generic_blocked = 0
    accepted_20mb = 0
    expected_marker_attacks = args.attack_count + args.large_attack_count
    expected_generic_attacks = args.attack_count + args.large_attack_count

    for result in results:
        if result.case.expected is not None and result.status != result.case.expected:
            failures += 1
        if result.case.attack == "marker_sqli" and result.status == 403:
            marker_blocked += 1
        if result.case.attack == "generic_sqli" and result.status == 403:
            generic_blocked += 1
        if (result.case.attack == "none"
                and result.case.size_bytes >= args.large_size_mb * 1024 * 1024
                and result.status == 200):
            accepted_20mb += 1

    statuses: dict[str, int] = {}
    for result in results:
        key = str(result.status) if result.status is not None else "ERR"
        statuses[key] = statuses.get(key, 0) + 1

    print("summary")
    print(f"  elapsed_sec={elapsed:.3f}")
    print(f"  statuses={statuses}")
    print(f"  expected_failures={failures}")
    print(f"  accepted_large_payloads={accepted_20mb}/{args.large_count}")
    print(f"  marker_sqli_blocked={marker_blocked}/{expected_marker_attacks}")
    print(
        f"  generic_sqli_blocked={generic_blocked}/{expected_generic_attacks}"
    )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
