#!/usr/bin/env python3
"""Generate large valid JSON documents for parser benchmarks.

Examples:
  python3 scripts/gen_large_json.py --size-mb 10 --output /tmp/large10.json
  python3 scripts/gen_large_json.py --size-mb 50 --output /tmp/large50.json
  python3 scripts/gen_large_json.py --size-mb 100 --output /tmp/large100.json
"""

from __future__ import annotations

import argparse
import sys


def generate(size_mb: float, output: str, corrupt_tail: bool) -> None:
    target = int(size_mb * 1024 * 1024)
    if target < 16:
        print("size too small", file=sys.stderr)
        sys.exit(1)

    written = 0
    i = 0
    with open(output, "w", encoding="utf-8") as f:
        f.write('{"items":[')
        written += len('{"items":[')

        first = True
        # Each record is roughly fixed-size; pad string to grow predictably.
        while written < target - 64:
            rec = (
                f'{"" if first else ","}'
                f'{{"id":{i},"name":"user-{i}",'
                f'"active":{"true" if i % 2 == 0 else "false"},'
                f'"score":{i % 1000},'
                f'"note":"padding-{"x" * 32}-{i}"}}'
            )
            first = False
            f.write(rec)
            written += len(rec)
            i += 1

        if corrupt_tail:
            # Leave a trailing comma so the document is invalid near the end.
            f.write(",]}")
            written += 3
        else:
            f.write("]}")
            written += 2

    print(f"wrote {output}: ~{written} bytes, {i} items, corrupt_tail={corrupt_tail}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate large JSON for ngx_json_guard")
    ap.add_argument("--size-mb", type=float, default=10.0, help="Approximate size in MiB")
    ap.add_argument("--output", "-o", required=True, help="Output file path")
    ap.add_argument(
        "--corrupt-tail",
        action="store_true",
        help="Make JSON invalid near the end (trailing comma)",
    )
    args = ap.parse_args()
    generate(args.size_mb, args.output, args.corrupt_tail)


if __name__ == "__main__":
    main()
