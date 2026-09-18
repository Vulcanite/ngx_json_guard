#!/usr/bin/env python3
"""Write the committed sample fixture and optional generated bodies.

The small object lives in git. Larger files go to an output directory
(default /tmp/jg-fixtures) so artifacts/ is not required.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMALL_SRC = ROOT / "benchmark" / "fixtures" / "small_object.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/jg-fixtures"),
        help="Directory for copied/generated fixtures",
    )
    ap.add_argument(
        "--sizes-mb",
        default="0.1,1",
        help="Comma-separated MiB sizes to generate (empty to skip)",
    )
    args = ap.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    dest_small = args.output_dir / "small_object.json"
    shutil.copy2(SMALL_SRC, dest_small)
    print(f"copied {dest_small} ({dest_small.stat().st_size} bytes)")

    sizes = [s.strip() for s in args.sizes_mb.split(",") if s.strip()]
    gen = ROOT / "scripts" / "gen_large_json.py"
    for size in sizes:
        out = args.output_dir / f"body_{size}m.json"
        subprocess.check_call(
            [sys.executable, str(gen), "--size-mb", size, "--output", str(out)]
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
